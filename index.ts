// index.ts
/// <reference path="./types.d.ts" />
import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import qrcode from 'qrcode-terminal';
import WAWebJS, { Message, Chat } from 'whatsapp-web.js';
import { db, initDb } from './db/db';
import express, { Request, Response } from 'express';
import QRCode from 'qrcode';
import helmet from 'helmet';
import cors from 'cors';

const { Client, LocalAuth, Message: MessageCtor } = WAWebJS as any;

/* ===========================
   Config
=========================== */
const OUTPUT_DIR = path.join(process.cwd(), 'out');
const RAW_PATH = path.join(OUTPUT_DIR, 'raw.jsonl');
const STATUS_PATH = path.join(OUTPUT_DIR, 'status.json');
const META_PATH = path.join(OUTPUT_DIR, 'meta.json');
const AUTH_DIR = path.join(process.cwd(), '.wwebjs_auth');

const BOOTSTRAP_CHAT_LIMIT = +(process.env.BOOTSTRAP_CHAT_LIMIT || 15);
const BOOTSTRAP_MSG_LIMIT  = +(process.env.BOOTSTRAP_MSG_LIMIT  || 20);

const HEARTBEAT_MS   = +(process.env.HEARTBEAT_MS || 30_000);
const MAX_RETRIES_BEFORE_AUTH_RESET = +(process.env.MAX_RETRIES_BEFORE_AUTH_RESET || 5);
const BASE_RETRY_MS  = +(process.env.BASE_RETRY_MS || 5_000);
const MAX_RETRY_MS   = +(process.env.MAX_RETRY_MS || 60_000);
const INIT_TIMEOUT_MS = +(process.env.INIT_TIMEOUT_MS || 90_000);
const QR_MAX_WAIT_MS = +(process.env.QR_MAX_WAIT_MS || 10 * 60 * 1000); // 10 minutes
const HEARTBEAT_FAILURES_BEFORE_RECONNECT = +(process.env.HEARTBEAT_FAILURES_BEFORE_RECONNECT || 2);

const LOG_PATH = path.join(OUTPUT_DIR, 'service.log');
const LOG_MAX_BYTES = +(process.env.LOG_MAX_BYTES || 10_000_000); // 10 MB
const LOG_KEEP = +(process.env.LOG_KEEP || 3); // keep service.log.1 .. .3
const BACKFILL_BATCH = +(process.env.BACKFILL_BATCH || 100);
const MAX_BACKFILL_MESSAGES_PER_RUN = +(process.env.MAX_BACKFILL_MESSAGES_PER_RUN || 800);
const MAX_TIER1_CHATS = 15;
const TIER1_TARGET_MESSAGES = 300;
const MAX_TIER2_CHATS = 20;
const TIER2_TARGET_MESSAGES = 50;
const MAX_TIER3_GROUP_CHATS = 5;
const TIER3_TARGET_MESSAGES = 20;
const MAX_BACKFILL_CHATS_PER_RUN = 5;
const BACKFILL_DELAY_BETWEEN_CHATS_MS = 1000;
const ACTION_KEYWORDS = [
  'tomorrow',
  'today',
  'address',
  'meet',
  'meeting',
  'dinner',
  'booking',
  'flight',
  'party',
  'appointment',
  'call',
  'deadline'
];
const PINNED_CHAT_IDS = (process.env.PINNED_CHAT_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
const PINNED_CONTACTS = (process.env.PINNED_CONTACTS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

/* ===========================
   Ensure output dir + DB
=========================== */
if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
initDb();

/* ===========================
   Status helpers
=========================== */
type ServiceState =
  | 'starting'
  | 'waiting_qr'
  | 'connected'
  | 'reconnecting'
  | 'needs_qr'
  | 'error'
  | 'shutting_down';

const status = {
  state: 'starting' as ServiceState,
  lastQrAt: 0,
  lastReadyAt: 0,
  lastMessageAt: 0,
  lastDbWriteAt: 0,   // NEW
  retryCount: 0,
  restartCount: 0,   // NEW
  details: '' as string,
  needsQr: false,
  lastError: null as string | null,
  humanMessage: '',
  lastStateChangeAt: Date.now(),
};

function writeStatus(partial: Partial<typeof status>) {
  const prevState = status.state;
  Object.assign(status, partial);
  if (partial.state && partial.state !== prevState) {
    status.lastStateChangeAt = Date.now();
  }
  try {
    fs.writeFileSync(
      STATUS_PATH,
      JSON.stringify({ ...status, now: Date.now() }, null, 2),
      'utf8'
    );
  } catch {}
}

/* ===========================
   Backfill metadata
=========================== */
type ChatCursorMeta = {
  oldestTs?: number;
  oldestMessageId?: string;
  lastBackfillAt?: number;
  backfillExhausted?: boolean;
  lastBackfillNewSaved?: number;
  lastBackfillDupes?: number;
};

type MetaState = {
  chatCursors: Record<string, ChatCursorMeta>;
  lastBackfillRun?: {
    lastRunAt?: number;
    lastRunSaved?: number;
    lastRunChats?: number;
    queuedCandidates?: number;
  };
  onboardingCompleted?: boolean;
};

const meta: MetaState = loadMeta();

function loadMeta(): MetaState {
  try {
    if (fs.existsSync(META_PATH)) {
      const data = fs.readFileSync(META_PATH, 'utf8');
      return { chatCursors: {}, ...JSON.parse(data) };
    }
  } catch (err: any) {
    console.warn('⚠️ Failed to load meta.json, starting fresh:', err?.message);
  }
  return { chatCursors: {} };
}

function persistMeta() {
  try {
    fs.writeFileSync(META_PATH, JSON.stringify(meta, null, 2), 'utf8');
  } catch (err: any) {
    console.error('⚠️ Failed to persist meta.json:', err?.message);
  }
}

function getCursorMeta(chatId: string): ChatCursorMeta | undefined {
  return meta.chatCursors[chatId];
}

function updateCursorAfterBatch(chatId: string, opts: { savedMessages: Message[]; dupes: number; exhausted: boolean }) {
  const saved = opts.savedMessages || [];
  const oldest = saved.reduce<{ ts?: number; id?: string }>((acc, m) => {
    const ts = (m.timestamp || 0) * 1000;
    if (acc.ts === undefined || ts < (acc.ts || 0)) {
      return { ts, id: (m.id as any)?._serialized || m.id?.id || m.id };
    }
    return acc;
  }, {});

  const existing = meta.chatCursors[chatId] || {};
  const next: ChatCursorMeta = {
    ...existing,
    oldestTs: oldest.ts ?? existing.oldestTs,
    oldestMessageId: oldest.id ?? existing.oldestMessageId,
    lastBackfillAt: Date.now(),
    backfillExhausted: opts.exhausted || false,
    lastBackfillNewSaved: saved.length,
    lastBackfillDupes: opts.dupes
  };

  // If we actually moved the cursor, backfillExhausted should reset
  if (saved.length > 0 && oldest.ts !== undefined) {
    next.backfillExhausted = opts.exhausted;
  }

  meta.chatCursors[chatId] = next;
  persistMeta();
}

/* ===========================
   Logging with rotation
=========================== */
function rotateLogIfNeeded() {
  try {
    const stats = fs.statSync(LOG_PATH);
    if (stats.size >= LOG_MAX_BYTES) {
      for (let i = LOG_KEEP; i >= 1; i--) {
        const src = i === 1 ? LOG_PATH : `${LOG_PATH}.${i - 1}`;
        const dest = `${LOG_PATH}.${i}`;
        if (fs.existsSync(src)) {
          try {
            fs.renameSync(src, dest);
          } catch {}
        }
      }
    }
  } catch {
    // no log yet
  }
}

function log(...args: any[]) {
  const ts = new Date().toISOString();
  const line = [ts, ...args].join(' ') + '\n';

  // console
  console.log(line.trim());

  // file
  try {
    rotateLogIfNeeded();
    fs.appendFileSync(LOG_PATH, line, 'utf8');
  } catch (err) {
    console.error('⚠️ Failed to write service.log:', err);
  }
}

/* ===========================
   Client factory
=========================== */
function createClient() {
  return new Client({
    authStrategy: new LocalAuth({ dataPath: './.wwebjs_auth' }),
    puppeteer: {
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    },
  });
}

let client: any = createClient();
const onboardingFlags = {
  inProgress: false
};

/* ===========================
   Backfill lock to avoid overlap
=========================== */
const backfillLock = { holder: null as string | null };

async function withBackfillLock<T>(name: string, fn: () => Promise<T>): Promise<T | undefined> {
  if (backfillLock.holder) {
    if (process.env.DEBUG_INTEL) {
      log(`DEBUG_INTEL: Backfill ${name} skipped, lock held by ${backfillLock.holder}`);
    }
    return;
  }
  backfillLock.holder = name;
  try {
    return await fn();
  } finally {
    backfillLock.holder = null;
  }
}

/* ===========================
   Contact cache
=========================== */
const contactCache = new Map<string, { displayName: string; savedName: string | null; pushname: string | null; timestamp: number }>();
const CONTACT_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

/* ===========================
   Call state management
=========================== */
interface CallState {
  id: string;
  chatId: string;
  callerId: string;
  calleeId?: string;
  isVideo: boolean;
  isGroup: boolean;
  status: 'pending' | 'connecting' | 'in_progress' | 'ended' | 'rejected' | 'missed';
  startTime: number;
  endTime?: number;
  durationMs?: number;
}

const activeCalls = new Map<string, CallState>();

/* ===========================
   QR and HTTP server
=========================== */
let currentQR: string | null = null;
let currentQRBase64: string | null = null;
let httpServer: any = null;

async function generateQRBase64(qrString: string): Promise<string> {
  try {
    return await QRCode.toDataURL(qrString, {
      width: 256,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      }
    });
  } catch (err) {
    log('❌ Failed to generate QR base64:', err);
    return '';
  }
}

function startHTTPServer() {
  const app = express();
  const PORT = process.env.HTTP_PORT || 3000;

  // Middleware
  app.use(express.json());
  app.use(helmet());

  const corsOrigins = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const allowAll = !process.env.NODE_ENV || process.env.NODE_ENV === 'development';
  app.use(cors({
    origin: (origin: any, callback: any) => {
      if (!origin) return callback(null, true);
      if (allowAll && corsOrigins.length === 0) return callback(null, true);
      if (corsOrigins.includes(origin)) return callback(null, true);
      return callback(new Error('CORS not allowed'), false);
    }
  }));

  // API Key authentication middleware
  const authenticate = (req: Request, res: Response, next: any) => {
    const authHeader = req.headers.authorization;
    const apiKey = process.env.API_KEY;

    if (!apiKey) {
      return res.status(500).json({ error: 'API key not configured' });
    }

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid authorization header' });
    }

    const token = authHeader.substring(7);
    if (token !== apiKey) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    next();
  };
  const rateLimiters: Record<string, { count: number; resetAt: number }> = {};
  function rateLimit(key: string, limit: number, windowMs: number) {
    const now = Date.now();
    const bucket = rateLimiters[key] || { count: 0, resetAt: now + windowMs };
    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + windowMs;
    }
    bucket.count += 1;
    rateLimiters[key] = bucket;
    return bucket.count <= limit;
  }

  const rateLimitMiddleware = (prefix: string, limit: number, windowMs: number) => (req: Request, res: Response, next: any) => {
    const key = `${prefix}:${req.ip}`;
    if (!rateLimit(key, limit, windowMs)) {
      return res.status(429).json({ error: 'Too many requests' });
    }
    next();
  };

  // QR endpoint - serves current QR as base64
  app.get('/qr', (req, res) => {
    if (!currentQRBase64) {
      return res.status(404).json({
        error: 'No QR code available',
        message: 'QR code will be available when service needs authentication'
      });
    }

    res.json({
      qr: currentQRBase64,
      timestamp: status.lastQrAt,
      expiresAt: status.lastQrAt + (5 * 60 * 1000), // QR expires in 5 minutes
      state: status.state
    });
  });

  // Status endpoint - comprehensive service health
  app.get('/status', (req, res) => {
    const uptime = Date.now() - (status.lastReadyAt || Date.now());
    const jsonFiles = ['messages.json', 'contacts.json', 'chats.json', 'calls.json'];
    const dbSize = jsonFiles
      .map(name => path.join(OUTPUT_DIR, name))
      .filter(p => fs.existsSync(p))
      .reduce((total, p) => total + fs.statSync(p).size, 0);

    res.json({
      state: status.state,
      uptime,
      lastQrAt: status.lastQrAt,
      lastReadyAt: status.lastReadyAt,
      lastMessageAt: status.lastMessageAt,
      lastDbWriteAt: status.lastDbWriteAt,
      retryCount: status.retryCount,
      restartCount: status.restartCount,
      details: status.details,
      needsQr: status.needsQr,
      lastError: status.lastError,
      humanMessage: status.humanMessage,
      lastStateChangeAt: status.lastStateChangeAt,
      databaseSize: dbSize,
      callsCaptured: activeCalls.size,
      version: '1.0.0',
      timestamp: Date.now(),
      backfill: {
        lastRunAt: meta.lastBackfillRun?.lastRunAt || null,
        lastRunSaved: meta.lastBackfillRun?.lastRunSaved || 0,
        lastRunChats: meta.lastBackfillRun?.lastRunChats || 0,
        queuedCandidates: meta.lastBackfillRun?.queuedCandidates || 0
      },
      cursorStats: {
        totalTracked: Object.keys(meta.chatCursors || {}).length,
        exhausted: Object.values(meta.chatCursors || {}).filter(c => c.backfillExhausted).length
      }
    });
  });

  // Health check endpoint for containers
  app.get('/health', (req, res) => {
    const isHealthy = status.state === 'connected' &&
                     (Date.now() - status.lastMessageAt) < (10 * 60 * 1000); // 10 minutes

    res.status(isHealthy ? 200 : 503).json({
      healthy: isHealthy,
      state: status.state,
      lastMessageAt: status.lastMessageAt,
      timestamp: Date.now()
    });
  });

  // API Routes - Messages
  app.get('/api/messages/recent-chats', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const chatsCount = Math.min(parseInt(req.query.chats as string) || 5, 50);
      const messagesPerChat = Math.min(parseInt(req.query.messages as string) || 10, 100);

      // Get recent chats using our SimpleDB
      const chats = (db as any).getChats() || [];
      const filteredChats = chats
        .filter((chat: any) => chat.name !== 'WhatsApp')
        .slice(0, chatsCount);

      const result = [];

      for (const chat of filteredChats) {
        const messages = (db as any).getMessagesByChat(chat.id, messagesPerChat) || [];

        if (messages.length > 0) {
          result.push({
            chatId: chat.id,
            chatName: chat.name,
            isGroup: chat.isGroup,
            messages: messages // Already in correct order (oldest first)
          });
        }
      }

      res.json({ chats: result });
    } catch (err: any) {
      log('❌ API Error /api/messages/recent-chats:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/messages/chat/:chatId', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const { chatId } = req.params;
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 500);
      const offset = parseInt(req.query.offset as string) || 0;

      // Use SimpleDB methods
      const allMessages = (db as any).getMessagesByChat(chatId, limit + offset) || [];
      const messages = allMessages.slice(offset, offset + limit);

      // Get total count
      const total = allMessages.length;

      res.json({
        messages: messages, // Already in correct order (oldest first)
        total,
        hasMore: (offset + limit) < total,
        chatId
      });
    } catch (err: any) {
      log('❌ API Error /api/messages/chat/:chatId:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/messages/chat/:chatId/since', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const { chatId } = req.params;
      const tsRaw = req.query.ts as any;
      const ts = Number(tsRaw);
      if (tsRaw === undefined || Number.isNaN(ts) || ts < 0) {
        return res.status(400).json({
          error: 'invalid_ts',
          detail: 'ts must be a non-negative number (ms)',
          chatId,
          tsRaw
        });
      }
      const limit = Math.min(parseInt(req.query.limit as string) || 200, 2000);

      const chats = (db as any).getChats?.() || [];
      const chatExists = chats.some((c: any) => c.id === chatId);
      const all = (db as any).getMessagesByChatSince?.(chatId, ts, limit + 1) || [];
      const messages = all.slice(0, limit);
      const total = all.length; // up to limit+1
      const hasMore = total > messages.length;

      res.json({
        chatId,
        messages,
        total,
        hasMore,
        truncated: hasMore
      });
    } catch (err: any) {
      log('❌ API Error /api/messages/chat/:chatId/since:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Contacts endpoint
  app.get('/api/contacts', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 200, 500);
      const contacts = (db as any).getContacts?.() || [];
      const chats = (db as any).getChats?.() || [];
      const chatMap = new Map<string, any>();
      for (const c of chats) chatMap.set(c.id, c);

      const rows = chats.map((chat: any) => {
        const contact = contacts.find((c: any) => c.id === chat.id);
        const displayCandidate = contact?.displayName || chat.name || chat.id;
        const displayName = preferBestName(chat.name, displayCandidate, `api-contact:${chat.id}`) || displayCandidate;
        return {
          chatId: chat.id,
          displayName,
          pushname: contact?.pushname || null,
          savedName: contact?.savedName || null,
          isGroup: !!chat.isGroup,
          lastMessageTs: chat.lastMessageTs || null,
          messageCount: chat.messageCount || 0
        };
      });

      rows.sort((a: any, b: any) => (b.lastMessageTs || 0) - (a.lastMessageTs || 0));

      res.json({ contacts: rows.slice(0, limit) });
    } catch (err: any) {
      log('❌ API Error /api/contacts:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/chats/active', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
      const includeGroups = (req.query.includeGroups as string) !== '0';
      const contacts = (db as any).getContacts?.() || [];
      const chats = (db as any).getChats?.() || [];

      const rows = chats
        .filter((chat: any) => includeGroups ? true : !chat.isGroup)
        .map((chat: any) => {
          const contact = contacts.find((c: any) => c.id === chat.id);
          const displayCandidate = contact?.displayName || chat.name || chat.id;
          const displayName = preferBestName(chat.name, displayCandidate, `api-active:${chat.id}`) || displayCandidate;
          return {
            chatId: chat.id,
            displayName,
            pushname: contact?.pushname || null,
            savedName: contact?.savedName || null,
            isGroup: !!chat.isGroup,
            lastMessageTs: chat.lastMessageTs || 0,
            messageCount: chat.messageCount || 0
          };
        })
        .sort((a: any, b: any) => (b.lastMessageTs || 0) - (a.lastMessageTs || 0));

      res.json(rows.slice(0, limit));
    } catch (err: any) {
      log('❌ API Error /api/chats/active:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/messages/contact/:contactId', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const { contactId } = req.params;
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 500);
      const offset = parseInt(req.query.offset as string) || 0;

      // Use SimpleDB methods
      const allMessages = (db as any).getRecentMessages(1000) || [];
      const filteredMessages = allMessages.filter((msg: any) => msg.senderId === contactId);
      const messages = filteredMessages.slice(offset, offset + limit);

      // Get contact info
      const contacts = (db as any).getContacts() || [];
      const contact = contacts.find((c: any) => c.id === contactId) || null;

      // Get total count
      const total = filteredMessages.length;

      res.json({
        messages: messages, // Already in correct order (oldest first)
        contact: contact,
        total,
        hasMore: (offset + limit) < total,
        contactId
      });
    } catch (err: any) {
      log('❌ API Error /api/messages/contact/:contactId:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/messages/recent', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 100, 1000);

      // Use SimpleDB methods
      const messages = (db as any).getRecentMessages(limit) || [];

      res.json({
        messages: messages, // Already in correct order (oldest first)
        total: messages.length,
        limit
      });
    } catch (err: any) {
      log('❌ API Error /api/messages/recent:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/messages/since', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const tsRaw = req.query.ts as any;
      const ts = Number(tsRaw);
      const path = '/api/messages/since';
      if (tsRaw === undefined || Number.isNaN(ts) || ts < 0) {
        return res.status(400).json({
          error: 'invalid_ts',
          detail: 'ts must be a non-negative number (ms)',
          tsRaw,
          path
        });
      }
      const limit = Math.min(parseInt(req.query.limit as string) || 500, 5000);

      const { messages, total, hasMore } = (db as any).getMessagesSince?.(ts, limit) || { messages: [], total: 0, hasMore: false };
      const truncated = hasMore && messages.length === limit;

      if (process.env.DEBUG_INTEL) {
        log(`DEBUG_INTEL: GET ${path} ts=${ts} limit=${limit} returned=${messages.length} total=${total} truncated=${truncated}`);
      }

      res.json({
        messages,
        total,
        hasMore,
        truncated
      });
    } catch (err: any) {
      log('❌ API Error /api/messages/since:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/messages/before', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const tsRaw = req.query.ts as any;
      const ts = Number(tsRaw);
      const path = '/api/messages/before';
      if (tsRaw === undefined || Number.isNaN(ts) || ts < 0) {
        return res.status(400).json({
          error: 'invalid_ts',
          detail: 'ts must be a non-negative number (ms)',
          tsRaw,
          path
        });
      }
      const limit = Math.min(parseInt(req.query.limit as string) || 500, 5000);

      const { messages, total, hasMore } = (db as any).getMessagesBefore?.(ts, limit) || { messages: [], total: 0, hasMore: false };
      const truncated = hasMore && messages.length === limit;

      if (process.env.DEBUG_INTEL) {
        log(`DEBUG_INTEL: GET ${path} ts=${ts} limit=${limit} returned=${messages.length} total=${total} truncated=${truncated}`);
      }

      res.json({
        messages,
        total,
        hasMore,
        truncated
      });
    } catch (err: any) {
      log('❌ API Error /api/messages/before:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // API Routes - Calls
  app.get('/api/calls/recent', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 500);

      // Use SimpleDB methods
      const calls = (db as any).getRecentCalls(limit) || [];

      res.json({
        calls: calls, // Already in correct order (oldest first)
        total: calls.length,
        limit
      });
    } catch (err: any) {
      log('❌ API Error /api/calls/recent:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/calls/since', authenticate, rateLimitMiddleware('api', 300, 60_000), async (req, res) => {
    try {
      const ts = parseInt(req.query.ts as string);
      if (!ts || isNaN(ts)) {
        return res.status(400).json({ error: 'Invalid timestamp parameter' });
      }

      // Use SimpleDB methods
      const allCalls = (db as any).getRecentCalls(1000) || [];
      const filteredCalls = allCalls.filter((call: any) => call.timestamp >= ts);

      res.json({
        calls: filteredCalls, // Already in correct order (oldest first)
        total: filteredCalls.length,
        since: ts
      });
    } catch (err: any) {
      log('❌ API Error /api/calls/since:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  httpServer = app.listen(PORT, () => {
    log(`🌐 HTTP server listening on port ${PORT}`);
    log(`📋 Public endpoints: /qr, /status, /health`);
    log(`🔐 API endpoints: /api/messages/*, /api/calls/*`);
  });

  return app;
}

let contactApiBroken = false;
const contactErrorSeenForId = new Set<string>();

async function resolveContactName(
  id: string,
  sourceMessage?: Message,
  chat?: Chat
): Promise<{ displayName: string; savedName: string | null; pushname: string | null }> {
  let savedName: string | null = null;
  let finalPushname: string | null = null;

  if (id === 'me') {
    return { displayName: 'me', savedName: null, pushname: null };
  }

  const cached = contactCache.get(id);
  if (cached && (Date.now() - cached.timestamp) < CONTACT_CACHE_TTL) {
    return {
      displayName: cached.displayName,
      savedName: cached.savedName,
      pushname: cached.pushname
    };
  }

  const raw = (sourceMessage as any)?._data ?? {};
  const notifyName = raw.notifyName as string | undefined;
  const msgPushname = raw.pushname as string | undefined;

    // Prefer chat name (for 1:1 chats this is often the contact name)
  const chatName =
    chat
      ? (
          chat.name ||
          (chat as any).formattedTitle ||
          undefined
        )
      : undefined;

  let baseDisplay =
    chat && chatName && chatName !== chat.id?._serialized
      ? chatName
      : undefined;

  baseDisplay = baseDisplay || notifyName || msgPushname || id;


  // 🔹 Try the contact API *once* per process, unless we've already marked it as broken
  if (!contactApiBroken) {
    try {
      const contact =
        sourceMessage && typeof (sourceMessage as any).getContact === 'function'
          ? await (sourceMessage as any).getContact()
          : await client.getContactById(id);

      savedName = contact.name ?? null;
      finalPushname = contact.pushname ?? finalPushname;

      const upgradedDisplay =
        contact.name ||
        contact.pushname ||
        baseDisplay;

      const result = {
        displayName: upgradedDisplay,
        savedName,
        pushname: finalPushname
      };

      contactCache.set(id, { ...result, timestamp: Date.now() });
      return result;
    } catch (err: any) {
      const msg = err?.message || '';

      // If WhatsApp internals changed (ContactMethods.*), treat contact API as broken for this process
      if (msg.includes('ContactMethods.getIsMyContact')) {
        contactApiBroken = true;
      }

      if (!contactErrorSeenForId.has(id)) {
        contactErrorSeenForId.add(id);
        console.warn('⚠️ Contact lookup failed; falling back to chat/message metadata', {
          contactId: id,
          message: msg
        });
      }
      // Fall through to base metadata
    }
  }

  const fallbackResult = {
    displayName: baseDisplay,
    savedName,
    pushname: finalPushname
  };

  contactCache.set(id, { ...fallbackResult, timestamp: Date.now() });
  return fallbackResult;
}

/* ===========================
   Name resolution
=========================== */

function resolvedChatName(chat: Chat): string {
  return (
    chat.name ||
    (chat as any).formattedTitle ||
    chat.id?._serialized ||
    'unknown'
  );
}

function isPhoneLike(name?: string | null): boolean {
  if (!name) return false;
  const cleaned = name.replace(/[^0-9]/g, '');
  const phoneish = /^[+0-9().\s-]+$/.test(name);
  return phoneish && cleaned.length >= 6;
}

function preferBestName(existing: string | null | undefined, incoming: string | null | undefined, ctx?: string): string | undefined {
  if (!incoming) return existing || undefined;
  if (!existing) return incoming;
  const existingIsPhone = isPhoneLike(existing);
  const incomingIsPhone = isPhoneLike(incoming);
  if (!existingIsPhone && incomingIsPhone) {
    if (process.env.DEBUG_INTEL) {
      log(`DEBUG_INTEL: Prevented name downgrade (${ctx || 'name'}) existing="${existing}" incoming="${incoming}"`);
    }
    return existing;
  }
  if (existingIsPhone && !incomingIsPhone) return incoming;
  return incoming;
}

/* ===========================
   Cursor-aware message fetch
=========================== */
async function fetchMessagesOlderThan(chatIdSerialized: string, cutoffTsMs: number, limit: number): Promise<{ messages: Message[]; oldestTsMs: number | null }> {
  if (!limit || limit <= 0) return { messages: [], oldestTsMs: null };

  const cutoffSeconds = Math.floor(cutoffTsMs / 1000);
  const result = await (client as any).pupPage.evaluate(
    async (chatId: string, cutoffTsSeconds: number, maxMessages: number) => {
      const w = window as any;
      const msgFilter = (m: any) => {
        if (m.isNotification) return false;
        return m.t < cutoffTsSeconds;
      };

      const chat = await w.WWebJS.getChat(chatId, { getAsModel: false });
      if (!chat) return { messages: [], oldestTs: null };

      const collectOlder = () => chat.msgs.getModelsArray().filter(msgFilter);

      let older = collectOlder();
      let noProgressRounds = 0;
      while (older.length < maxMessages) {
        const beforeCount = older.length;
        const loadedMessages = await w.Store.ConversationMsgs.loadEarlierMsgs(chat);
        if (!loadedMessages || !loadedMessages.length) break;
        older = collectOlder();
        if (older.length <= beforeCount) {
          noProgressRounds += 1;
          if (noProgressRounds >= 2) break;
        } else {
          noProgressRounds = 0;
        }
      }

      older.sort((a: any, b: any) => (a.t > b.t ? 1 : -1));
      if (older.length > maxMessages) {
        older = older.slice(-maxMessages);
      }

      const mapped = older.map((m: any) => w.WWebJS.getMessageModel(m));
      const oldestTs = older.length ? older[0].t : null;
      return { messages: mapped, oldestTs };
    },
  chatIdSerialized,
  cutoffSeconds,
  limit
);

const messages = (result?.messages || []).map((m: any) => new MessageCtor(client, m));
const oldestTsMs = result?.oldestTs !== null && result?.oldestTs !== undefined ? (result.oldestTs as number) * 1000 : null;
return { messages, oldestTsMs };
}

/* ===========================
   Targeted backfill helper
   - Used for onboarding + slow fill
=========================== */
async function backfillChatToTarget(chat: Chat, target: number, totals: { saved: number }, seen: Set<string>) {
  if (seen.has(chat.id._serialized)) return;
  seen.add(chat.id._serialized);
  if (status.state !== 'connected') return;
  const chatId = chat.id._serialized;
  const existingCount = (db as any).getMessageCount?.(chatId) ?? ((db as any).getMessagesByChat(chatId, target) || []).length;
  if (existingCount >= target) return;
  const cursor = getCursorMeta(chatId);
  if (cursor?.backfillExhausted) return;
  let remaining = target - existingCount;

  while (remaining > 0 && totals.saved < MAX_BACKFILL_MESSAGES_PER_RUN) {
    if (status.state !== 'connected') return;
    const batchLimit = Math.min(BACKFILL_BATCH, remaining, MAX_BACKFILL_MESSAGES_PER_RUN - totals.saved);
    if (batchLimit <= 0) break;
    const cutoffTs =
      cursor?.oldestTs ??
      (db as any).getOldestMessage?.(chatId)?.ts ??
      Date.now();

    if (process.env.DEBUG_INTEL) {
      log(`DEBUG_INTEL: Targeted backfill ${resolvedChatName(chat)} target=${target} existing=${existingCount} remaining=${remaining} cutoffTs=${cutoffTs}`);
    }

    let messages: Message[] = [];
    let oldestTsMs: number | null = null;
    try {
      const res = await fetchMessagesOlderThan(chatId, cutoffTs, batchLimit);
      messages = res.messages;
      oldestTsMs = res.oldestTsMs;
    } catch (err: any) {
      log(`⚠️ Targeted backfill fetch error for ${resolvedChatName(chat)}: ${err?.message}`);
      break;
    }

    let dupes = 0;
    const newSaved: Message[] = [];
    for (const m of messages) {
      const msgId = (m as any).id?._serialized || (m as any).id?.id || (m as any).id;
      if (msgId && (db as any).hasMessage?.(msgId)) {
        dupes += 1;
        continue;
      }
      await saveMessage(m, chat);
      newSaved.push(m);
    }

    totals.saved += newSaved.length;
    remaining -= newSaved.length;
    const dupRate = messages.length ? dupes / messages.length : 0;
    const exhausted = messages.length === 0 || (oldestTsMs !== null && oldestTsMs >= cutoffTs);
    const stalled = dupRate > 0.8 || exhausted;

    updateCursorAfterBatch(chatId, { savedMessages: newSaved, dupes, exhausted });

    if (process.env.DEBUG_INTEL) {
      log(`DEBUG_INTEL: Targeted backfill stats chat=${chatId} fetched=${messages.length} saved=${newSaved.length} dupes=${dupes} dupRate=${(dupRate*100).toFixed(1)}% exhausted=${exhausted} stalled=${stalled} cursor=${getCursorMeta(chatId)?.oldestTs || 'n/a'}`);
    }

    if (stalled) break;
    await new Promise(resolve => setTimeout(resolve, BACKFILL_DELAY_BETWEEN_CHATS_MS));
  }
}

/* ===========================
   Scoring helpers
=========================== */
function computeKeywordBoost(chatId: string): number {
  const recent = ((db as any).getRecentTextMessages?.(chatId, 40) || []) as any[];
  const regex = new RegExp(`\\b(${ACTION_KEYWORDS.join('|')})\\b`, 'i');
  const hasKeyword = recent.some(m => typeof m.body === 'string' && regex.test(m.body));
  return hasKeyword ? 15 : 0;
}

function isPinnedChat(chat: Chat): boolean {
  const chatId = chat.id?._serialized || '';
  if (PINNED_CHAT_IDS.includes(chatId)) return true;

  const name = resolvedChatName(chat).toLowerCase();
  return PINNED_CONTACTS.some(fragment => fragment && name.includes(fragment));
}

function computeTargetForScore(score: number, pinned: boolean): number {
  const base = 50;
  const max = pinned ? 1000 : 600;
  const scaled = base + Math.round(score);
  return Math.max(base, Math.min(max, scaled));
}

/* ===========================
   Save message
=========================== */
async function saveMessage(m: Message, chat: Chat) {
  const senderId = m.fromMe ? 'me' : (m.author || m.from || chat.id._serialized);

  const resolvedNames = await resolveContactName(senderId, m, chat);
  const savedName = resolvedNames.savedName;
  const pushname = resolvedNames.pushname;

  const notifyName = (m as any)._data?.notifyName || null;
  const chatName = resolvedChatName(chat);

  const displayFallback = chatName || notifyName || senderId;
  const incomingDisplay =
    savedName ||
    pushname ||
    (resolvedNames.displayName && resolvedNames.displayName !== senderId
      ? resolvedNames.displayName
      : undefined) ||
    displayFallback;
  const existingContact = (db as any).getContacts?.().find((c: any) => c.id === senderId);
  const displayName = preferBestName(existingContact?.displayName, incomingDisplay, `contact:${senderId}`) || displayFallback;

  let participantId: string | null = null;
  let participantName: string | null = null;
  if (chat.isGroup && m.author) {
    participantId = m.author;
    const part = await resolveContactName(participantId, m);
    participantName = part.displayName;
  }

  const mediaMeta =
    m.type && m.type !== 'chat'
      ? {
          type: m.type,
          mimetype: (m as any)._data?.mimetype,
          filename: (m as any)._data?.filename || null,
          filesize: (m as any)._data?.size || null,
          durationMs: (m as any)._data?.duration || null,
        }
      : null;

  const record = {
  id: m.id.id,
  chatId: chat.id._serialized,
  senderId,
  savedName,
  pushname,
  displayName,
    participantId,
    participantName,
    fromMe: m.fromMe,
    type: m.type || 'unknown',
    body: m.type === 'chat' ? m.body : null,
    ts: (m.timestamp || 0) * 1000,
    mimetype: mediaMeta?.mimetype || null,
    filename: mediaMeta?.filename || null,
    filesize: mediaMeta?.filesize || null,
    durationMs: mediaMeta?.durationMs || null,
  };

  // Write to raw JSONL first (most important)
  try {
    fs.appendFileSync(RAW_PATH, JSON.stringify(record) + '\n', 'utf8');
  } catch (err: any) {
    console.error('❌ Failed to write to raw JSONL:', {
      message: err?.message,
      stack: err?.stack,
      messageId: m.id.id
    });
    return; // Don't continue if we can't log the raw message
  }

  // Database operations with comprehensive error handling
  try {
    // Use SimpleDB methods
    (db as any).saveMessage(record);

    status.lastMessageAt = Date.now();
    status.lastDbWriteAt = Date.now();

  } catch (err: any) {
    console.error('❌ Database operation failed:', {
      message: err?.message,
      stack: err?.stack,
      name: err?.name,
      timestamp: new Date().toISOString(),
      messageId: m.id.id,
      chatId: chat.id._serialized,
      operation: 'saveMessage'
    });
    // Don't rethrow - we still have the raw JSONL log
  }

  // Update chat name in DB, preferring non-phone-like names
  const existingChat = (db as any).getChats?.().find((c: any) => c.id === chat.id._serialized);
  const preferredChatName = preferBestName(existingChat?.name, resolvedChatName(chat), `chat:${chat.id._serialized}`) || resolvedChatName(chat);
  if (preferredChatName && preferredChatName !== existingChat?.name && (db as any).updateChatName) {
    (db as any).updateChatName(chat.id._serialized, preferredChatName);
  }

  log(`💬 New message in ${preferredChatName || displayName}`);
}

/* ===========================
   Save call
=========================== */
async function saveCall(callEvent: any) {
  try {
    const callState = activeCalls.get(callEvent.id);
    if (!callState) {
      log(`📞 Call event (no active state): ${callEvent.id}`);
      return;
    }

    const callRecord = {
      id: callState.id,
      chatId: callState.chatId,
      callerId: callState.callerId,
      calleeId: callState.calleeId,
      isVideo: callState.isVideo,
      isGroup: callState.isGroup,
      timestamp: callState.startTime,
      durationMs: callState.durationMs,
      status: callState.status,
      endTimestamp: callState.endTime,
    };

    // Write to raw JSONL first (backup)
    const rawCallPath = path.join(OUTPUT_DIR, 'calls.jsonl');
    fs.appendFileSync(rawCallPath, JSON.stringify({
      ...callRecord,
      rawEvent: callEvent,
      capturedAt: Date.now()
    }) + '\n', 'utf8');

    // Use SimpleDB methods
    (db as any).saveCall(callRecord);

    // Update status
    status.lastDbWriteAt = Date.now();

    log(`📞 Call saved: ${callState.isVideo ? '🎥' : '📞'} ${callState.status} (${callState.durationMs ? Math.round(callState.durationMs / 1000) + 's' : 'unknown duration'})`);

    // Clean up completed calls from memory
    if (['ended', 'rejected', 'missed'].includes(callState.status)) {
      activeCalls.delete(callEvent.id);
    }

  } catch (err: any) {
    console.error('❌ Call save failed:', {
      message: err?.message,
      stack: err?.stack,
      name: err?.name,
      timestamp: new Date().toISOString(),
      callId: callEvent.id
    });
  }
}

/* ===========================
   Handle call events
=========================== */
function setupCallHandlers(client: any) {
  // Main call event
  client.on('call', async (callEvent: any) => {
    try {
      log(`📞 Call initiated: ${callEvent.id} ${callEvent.isVideo ? '🎥' : '📞'}`);

      const callState: CallState = {
        id: callEvent.id,
        chatId: callEvent.to, // The chat/group being called
        callerId: callEvent.from,
        calleeId: callEvent.isGroup ? undefined : callEvent.to,
        isVideo: callEvent.isVideo || false,
        isGroup: callEvent.isGroup || false,
        status: 'pending',
        startTime: Date.now(),
      };

      activeCalls.set(callEvent.id, callState);

    } catch (err: any) {
      console.error('❌ Call event handling failed:', {
        message: err?.message,
        stack: err?.stack,
        callId: callEvent?.id
      });
    }
  });

  // Call state changes
  client.on('call:state_change', async (callEvent: any) => {
    try {
      const existingCall = activeCalls.get(callEvent.id);
      if (!existingCall) {
        log(`📞 Call state change for unknown call: ${callEvent.id}`);
        return;
      }

      // Update call state
      const updatedCall: CallState = {
        ...existingCall,
        status: callEvent.state || existingCall.status,
      };

      // Calculate duration if call is ending
      if (['ended', 'rejected', 'missed'].includes(callEvent.state)) {
        updatedCall.endTime = Date.now();
        updatedCall.durationMs = updatedCall.endTime - updatedCall.startTime;
      }

      activeCalls.set(callEvent.id, updatedCall);

      // Save to database when call completes
      if (['ended', 'rejected', 'missed'].includes(callEvent.state)) {
        await saveCall(callEvent);
      }

      log(`📞 Call ${callEvent.id} state: ${callEvent.state}`);

    } catch (err: any) {
      console.error('❌ Call state change handling failed:', {
        message: err?.message,
        stack: err?.stack,
        callId: callEvent?.id
      });
    }
  });
}

/* ===========================
   Bootstrap
=========================== */
async function bootstrap() {
  const chats: Chat[] = await client.getChats();
  const filtered = chats
    .filter((c: Chat) => resolvedChatName(c) !== 'WhatsApp')
    .slice(0, BOOTSTRAP_CHAT_LIMIT);

  log(`📂 Found ${chats.length} chats`);
  for (const chat of filtered) {
    log(`➡️ Chat: ${resolvedChatName(chat)}`);
    const messages = await chat.fetchMessages({ limit: BOOTSTRAP_MSG_LIMIT });
    const savedForChat: Message[] = [];
    let dupes = 0;
    for (const m of messages) {
      const msgId = (m as any).id?._serialized || (m as any).id?.id || (m as any).id;
      if (msgId && (db as any).hasMessage?.(msgId)) {
        dupes += 1;
        continue;
      }
      await saveMessage(m, chat);
      savedForChat.push(m);
    }
    if (savedForChat.length > 0) {
      updateCursorAfterBatch(chat.id._serialized, {
        savedMessages: savedForChat,
        dupes,
        exhausted: false
      });
    }
  }
  log('💾 Saved messages to raw.jsonl and database');
}

/* ===========================
   Onboarding Backfill (one-time)
   Phase A: breadth to 50 msgs for top recent 1:1 (30 chats)
   Phase B: depth to 200 msgs for top 1:1 (10 chats)
=========================== */
async function runOnboardingBackfill() {
  if (meta.onboardingCompleted || onboardingFlags.inProgress) return;
  onboardingFlags.inProgress = true;
  await withBackfillLock('onboarding', async () => {
    if (meta.onboardingCompleted) return;
    const totals = { saved: 0 };
    const seen = new Set<string>();

    const runPhase = async (chats: Chat[], target: number, maxChats: number, label: string) => {
      let processed = 0;
      for (const chat of chats) {
        if (processed >= maxChats) break;
        if (status.state !== 'connected') return;
        if (chat.isGroup) continue;
        await backfillChatToTarget(chat, target, totals, seen);
        processed += 1;
        if (totals.saved >= MAX_BACKFILL_MESSAGES_PER_RUN) break;
        await new Promise(resolve => setTimeout(resolve, BACKFILL_DELAY_BETWEEN_CHATS_MS));
      }
    };

    try {
      const chats = await client.getChats();
      const directChats = chats
        .filter((c: Chat) => !c.isGroup && resolvedChatName(c) !== 'WhatsApp');

      // Phase A: breadth to 50 for top 30 recent 1:1
      const topRecent = directChats
        .sort((a: any, b: any) => {
          const aTs = (db as any).getLatestMessage?.(a.id._serialized)?.ts || 0;
          const bTs = (db as any).getLatestMessage?.(b.id._serialized)?.ts || 0;
          return bTs - aTs;
        });
      await runPhase(topRecent, 50, 30, 'breadth');

      // Phase B: depth to 200 for top 10 by recency + message count
      const topDepth = directChats
        .map((c: Chat) => {
          const latest = (db as any).getLatestMessage?.(c.id._serialized)?.ts || 0;
          const count = (db as any).getMessageCount?.(c.id._serialized) || 0;
          return { chat: c, score: latest + count };
        })
        .sort((a: any, b: any) => b.score - a.score)
        .map((x: any) => x.chat);
      await runPhase(topDepth, 200, 10, 'depth');

      meta.onboardingCompleted = true;
      persistMeta();
    } catch (err: any) {
      log(`⚠️ Onboarding backfill failed: ${err?.message}`);
    } finally {
      onboardingFlags.inProgress = false;
    }
  });
}

/* ===========================
   Slow fill scheduler (post-onboarding)
   - Round robin 1:1 chats to reach 50 msgs
=========================== */
const SLOW_FILL_INTERVAL_MS = 30 * 60 * 1000;
let slowFillIndex = 0;

async function slowFillTick() {
  if (onboardingFlags.inProgress) return;
  if (status.state !== 'connected') return;
  await withBackfillLock('slow-fill', async () => {
    if (status.state !== 'connected') return;
    const totals = { saved: 0 };
    const seen = new Set<string>();

    try {
      const chats = await client.getChats();
      const directs = chats.filter((c: Chat) => !c.isGroup && resolvedChatName(c) !== 'WhatsApp');
      if (directs.length === 0) return;

      // Round-robin starting point
      const ordered = [...directs.slice(slowFillIndex), ...directs.slice(0, slowFillIndex)];
      slowFillIndex = (slowFillIndex + 3) % directs.length; // advance pointer modestly

      let processed = 0;
      for (const chat of ordered) {
        if (processed >= MAX_BACKFILL_CHATS_PER_RUN) break;
        if (status.state !== 'connected') return;

        const count = (db as any).getMessageCount?.(chat.id._serialized) || 0;
        if (count >= 50) continue;
        await backfillChatToTarget(chat, 50, totals, seen);
        processed += 1;
        if (totals.saved >= MAX_BACKFILL_MESSAGES_PER_RUN) break;
        await new Promise(resolve => setTimeout(resolve, BACKFILL_DELAY_BETWEEN_CHATS_MS));
      }
    } catch (err: any) {
      if (process.env.DEBUG_INTEL) {
        log(`DEBUG_INTEL: Slow fill tick error: ${err?.message}`);
      }
    }
  });
}

function scheduleSlowFill() {
  setInterval(() => {
    slowFillTick();
  }, SLOW_FILL_INTERVAL_MS);
}
/* ===========================
   Smart Backfill worker
=========================== */
async function smartBackfill() {
  await withBackfillLock('smart', async () => {
    try {
      if (status.state !== 'connected') {
        log(`🔄 Smart backfill skipped: client state=${status.state}`);
        return;
      }

      log(`🔄 Smart Backfill: scanning chats with scoring…`);

      let chats: Chat[];
      try {
        chats = await client.getChats();
      } catch (err: any) {
        log(`⚠️ Smart backfill: unable to fetch chats: ${err?.message}`);
        return;
      }

      const eligibleChats = chats.filter(
        (c: Chat) =>
          resolvedChatName(c) !== 'WhatsApp' &&
          c.id?._serialized !== 'status@broadcast'
      );

      const now = Date.now();
      const candidates: Array<{
        chat: Chat;
        score: number;
        target: number;
        existingCount: number;
        missingCount: number;
        cutoffTs: number;
        pinned: boolean;
      }> = [];

      for (const chat of eligibleChats) {
        try {
          const chatId = chat.id._serialized;
          const cursor = getCursorMeta(chatId);
          if (cursor?.backfillExhausted) {
            continue;
          }

          const latest = (db as any).getLatestMessage?.(chatId);
          const latestTs = latest?.ts ?? null;
          const count24h = (db as any).getMessageCountSince?.(chatId, now - 24 * 60 * 60 * 1000) || 0;
          const count7d = (db as any).getMessageCountSince?.(chatId, now - 7 * 24 * 60 * 60 * 1000) || 0;
          const keywordBoost = computeKeywordBoost(chatId);
          const pinned = isPinnedChat(chat);

          const recencyScore = latestTs
            ? Math.max(0, 1 - (now - latestTs) / (14 * 24 * 60 * 60 * 1000)) * 70
            : 0;
          const activityScore = count24h * 5 + count7d * 1;
          const score = recencyScore + activityScore + keywordBoost + (pinned ? 40 : 0);

          const target = computeTargetForScore(score, pinned);
          const existingCount =
            (db as any).getMessageCount?.(chatId) ??
            ((db as any).getMessagesByChat(chatId, target) || []).length;
          const missingCount = target - existingCount;
          if (missingCount <= 0) continue;

          const cutoffTs =
            cursor?.oldestTs ??
            (db as any).getOldestMessage?.(chatId)?.ts ??
            Date.now();

          candidates.push({
            chat,
            score,
            target,
            existingCount,
            missingCount,
            cutoffTs,
            pinned
          });
        } catch (err: any) {
          log(`⚠️ Skipping chat ${resolvedChatName(chat)} due to scoring error: ${err?.message}`);
        }
      }

      meta.lastBackfillRun = {
        lastRunAt: Date.now(),
        lastRunSaved: 0,
        lastRunChats: 0,
        queuedCandidates: candidates.length
      };
      persistMeta();

      if (candidates.length === 0) {
        log(`🔄 Smart backfill: nothing to do (no eligible candidates)`);
        return;
      }

      candidates.sort((a, b) => b.score - a.score);

      let processedCount = 0;
      let totalSaved = 0;

      for (const candidate of candidates) {
        if (processedCount >= MAX_BACKFILL_CHATS_PER_RUN) break;
        if (totalSaved >= MAX_BACKFILL_MESSAGES_PER_RUN) break;

        const { chat, target, existingCount, missingCount } = candidate;
        const batchLimit = Math.min(
          BACKFILL_BATCH,
          missingCount,
          MAX_BACKFILL_MESSAGES_PER_RUN - totalSaved
        );
        if (batchLimit <= 0) continue;

        const cutoffTs = candidate.cutoffTs || Date.now();
        log(
          `📥 Backfill ${resolvedChatName(chat)} score=${candidate.score.toFixed(
            1
          )} target=${target} existing=${existingCount} cutoffTs=${cutoffTs}`
        );

        let messages: Message[] = [];
        let oldestTsMs: number | null = null;
        try {
          const res = await fetchMessagesOlderThan(chat.id._serialized, cutoffTs, batchLimit);
          messages = res.messages;
          oldestTsMs = res.oldestTsMs;
        } catch (chatErr: any) {
          log(
            `⚠️ Skipping chat ${resolvedChatName(chat)} due to fetch error: ${chatErr?.message}`
          );
          continue;
        }

        let dupes = 0;
        const newSaved: Message[] = [];

        for (const m of messages) {
          const msgId = (m as any).id?._serialized || (m as any).id?.id || (m as any).id;
          if (msgId && (db as any).hasMessage?.(msgId)) {
            dupes += 1;
            continue;
          }
          await saveMessage(m, chat);
          newSaved.push(m);
        }

        totalSaved += newSaved.length;
        const dupRate = messages.length ? dupes / messages.length : 0;
        const exhausted = messages.length === 0 || (oldestTsMs !== null && oldestTsMs >= cutoffTs);
        const stalled = dupRate > 0.8 || exhausted;

        updateCursorAfterBatch(chat.id._serialized, {
          savedMessages: newSaved,
          dupes,
          exhausted
        });

        meta.lastBackfillRun = {
          lastRunAt: Date.now(),
          lastRunSaved: (meta.lastBackfillRun?.lastRunSaved || 0) + newSaved.length,
          lastRunChats: (meta.lastBackfillRun?.lastRunChats || 0) + 1,
          queuedCandidates: meta.lastBackfillRun?.queuedCandidates || candidates.length
        };
        persistMeta();

        log(
          `📊 Backfill ${resolvedChatName(chat)} fetched=${messages.length} newSaved=${newSaved.length} dupes=${dupes} dupRate=${(
            dupRate * 100
          ).toFixed(1)}% cursor=${getCursorMeta(chat.id._serialized)?.oldestTs || 'n/a'} exhausted=${exhausted}`
        );
        if (stalled) {
          log(`⚠️ Pagination not advancing for ${resolvedChatName(chat)}; stopping this chat`);
        }

        processedCount += 1;

        if (totalSaved >= MAX_BACKFILL_MESSAGES_PER_RUN) {
          log(`⚠️ Backfill run message cap reached (${MAX_BACKFILL_MESSAGES_PER_RUN})`);
          break;
        }

        await new Promise(resolve => setTimeout(resolve, BACKFILL_DELAY_BETWEEN_CHATS_MS));
      }

      if (processedCount > 0) {
        log(`✅ Smart backfill complete: processed ${processedCount} chats, saved ${totalSaved}`);
      } else {
        log(`🔄 Smart backfill: nothing to do (all tier targets satisfied for now)`);
      }
    } catch (err: any) {
      console.error("❌ Smart backfill error:", {
        message: err?.message,
        stack: err?.stack,
        name: err?.name,
        timestamp: new Date().toISOString()
      });
    }
  });
}

/* ===========================
   Smart Backfill scheduler
=========================== */
function scheduleSmartBackfill() {
  // Initial run: 15 minutes after login (longer delay for stability)
  setTimeout(() => {
    log("🕒 Running initial smart backfill (15m after login)...");
    smartBackfill();
  }, 15 * 60 * 1000);

  const HOUR_MS = 60 * 60 * 1000;

  setInterval(() => {
    smartBackfill();
  }, HOUR_MS);
}


/* ===========================
   Event handlers
=========================== */
function setupEventHandlers(c: any) {
  c.on('qr', async (qr: string) => {
    currentQR = qr;
    currentQRBase64 = await generateQRBase64(qr);

    writeStatus({
      state: 'waiting_qr',
      lastQrAt: Date.now(),
      details: 'Scan the QR in WhatsApp → Linked Devices',
      needsQr: true,
      lastError: null,
      humanMessage: 'Waiting for you to scan the WhatsApp QR code.'
    });

    console.log(
      '\n🔐 Scan this QR in WhatsApp: Settings → Linked Devices → Link a Device\n'
    );
    qrcode.generate(qr, { small: true });

    // Start HTTP server when QR is available
    if (!httpServer) {
      startHTTPServer();
    }
  });

  c.on('ready', async () => {
    hasEverBeenReady = true;
    isReconnecting = false;
    writeStatus({
      state: 'connected',
      lastReadyAt: Date.now(),
      details: '',
      needsQr: false,
      lastError: null,
      humanMessage: 'Connected to WhatsApp and ready to ingest messages.'
    });
    log('✅ WhatsApp client is ready!');
    try {
      await bootstrap();
      await runOnboardingBackfill();
      scheduleSlowFill();
      scheduleSmartBackfill();
      // No more immediate backfill - smart backfill starts after 15 minutes
    } catch (err: any) {
      writeStatus({
        state: 'error',
        details: `Bootstrap failed: ${err?.message || err}`,
        lastError: err?.message || 'Bootstrap failed',
        humanMessage: 'Connected, but bootstrap failed; check logs.'
      });
      console.error('❌ Bootstrap error:', {
        message: err?.message,
        stack: err?.stack,
        name: err?.name,
        timestamp: new Date().toISOString()
      });
    }
  });

  c.on('message_create', async (m: Message) => {
    try {
      const chat = await m.getChat();
      await saveMessage(m, chat);
    } catch (err: any) {
      console.error('❌ Failed to save live message:', {
        message: err?.message,
        stack: err?.stack,
        name: err?.name,
        timestamp: new Date().toISOString(),
        messageId: m?.id?.id || 'unknown'
      });
    }
  });

  c.on('disconnected', async (reason: string) => {
    writeStatus({
      state: 'reconnecting',
      details: `Disconnected: ${reason}`,
      humanMessage: 'Disconnected from WhatsApp; attempting to reconnect.',
      needsQr: false,
      lastError: reason || null
    });
    log(`⚠️ Client disconnected: ${reason}. Reconnecting…`);
    await scheduleReconnect();
  });
}


/* ===========================
   Reconnect & auth reset
=========================== */
let reconnectTimer: NodeJS.Timeout | null = null;
let shuttingDown = false;
let hasEverBeenReady = false;
let isInitializing = false;
let isReconnecting = false;
let consecutiveHeartbeatFailures = 0;

async function safeDestroy() {
  try {
    await client.destroy();
  } catch {}
}

async function scheduleReconnect() {
  if (shuttingDown) return;
  if (status.needsQr && status.state === 'needs_qr') {
    log('⏳ Reconnect skipped: service is waiting for a new QR scan.');
    return;
  }
  if (isInitializing) {
    log('⏳ Reconnect skipped: initialization in progress.');
    return;
  }
  if (isReconnecting) {
    log('⏳ Reconnect already scheduled/in progress; skipping.');
    return;
  }

  isReconnecting = true;

  status.retryCount += 1;
  status.restartCount += 1;

  const delay = Math.min(
    BASE_RETRY_MS * Math.pow(2, status.retryCount - 1),
    MAX_RETRY_MS
  );
  writeStatus({
    state: 'reconnecting',
    details: `Retry #${status.retryCount} in ${delay}ms`,
    humanMessage: `Reconnecting to WhatsApp (retry #${status.retryCount})…`,
    lastError: null,
    needsQr: false,
  });

  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(async () => {
    try {
      isInitializing = true;
      await safeDestroy();
      client = createClient();
    setupEventHandlers(client);
    setupCallHandlers(client);

    if (status.retryCount > MAX_RETRIES_BEFORE_AUTH_RESET) {
      log('❌ Too many retries → clearing auth and requiring QR scan.');
      writeStatus({
        state: 'needs_qr',
        details: 'Session expired. Clearing auth; will request new QR.',
        needsQr: true,
        lastError: 'Too many reconnect attempts; session has been reset and requires a new QR scan.',
        humanMessage: 'Session expired. Please open WhatsApp → Linked Devices and rescan the QR code.'
      });
      try {
        fs.rmSync(AUTH_DIR, { recursive: true, force: true });
        fs.rmSync('.wwebjs_cache', { recursive: true, force: true });
      } catch {}
      status.retryCount = 0;
      consecutiveHeartbeatFailures = 0;
      isInitializing = false;
      isReconnecting = false;
      return;
    }

    const initPromise = client.initialize();
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('InitTimeout')), INIT_TIMEOUT_MS)
      );

      await Promise.race([initPromise, timeoutPromise]);
    } catch (err: any) {
      console.error('⚠️ Init failed:', {
        message: err?.message,
        stack: err?.stack,
        name: err?.name,
        timestamp: new Date().toISOString()
      });
      writeStatus({
        state: 'error',
        details: `Reconnect init failed: ${err?.message || err}`,
        lastError: err?.message || 'Reconnect init failed',
        humanMessage: 'Reconnect failed; will retry shortly.',
        needsQr: status.needsQr
      });
    } finally {
      isInitializing = false;
      isReconnecting = false;
    }
  }, delay);
}
/* ===========================
   Heartbeat
=========================== */
setInterval(async () => {
  const now = Date.now();

  if (
    status.state === 'waiting_qr' &&
    status.lastQrAt &&
    (now - status.lastQrAt) > QR_MAX_WAIT_MS
  ) {
    log('⚠️ QR wait exceeded threshold; resetting auth and requesting new QR.');
    try {
      fs.rmSync(AUTH_DIR, { recursive: true, force: true });
    } catch {}
    status.retryCount = 0;
    writeStatus({
      state: 'needs_qr',
      details: 'QR wait exceeded; resetting auth.',
      needsQr: true,
      lastError: 'QR expired; requesting a fresh QR scan.',
      humanMessage: 'QR expired; requesting a fresh QR scan.'
    });
    return;
  }

  if (status.needsQr && status.state === 'needs_qr') {
    log('⏳ Heartbeat: waiting for QR scan; skipping reconnect checks.');
    writeStatus({});
    return;
  }

  if (!hasEverBeenReady) return;
  if (isInitializing) {
    const stuckMs = Date.now() - status.lastStateChangeAt;
    if (stuckMs > INIT_TIMEOUT_MS * 2) {
      log('⚠️ Heartbeat: init appears stuck; forcing reconnect.');
      isInitializing = false;
      isReconnecting = false;
      try {
        await scheduleReconnect();
      } catch (err: any) {
        log(`❌ Heartbeat: failed to schedule reconnect after stuck init: ${err?.message || err}`);
      }
    } else {
      log('⏳ Heartbeat: init in progress; skipping state check.');
    }
    return;
  }

  try {
    const s = await client.getState();
    if (s !== 'CONNECTED') {
      consecutiveHeartbeatFailures += 1;
      log(`⚠️ Heartbeat: client state = ${s}. Triggering reconnect.`);
      if (!isReconnecting && !isInitializing && consecutiveHeartbeatFailures >= HEARTBEAT_FAILURES_BEFORE_RECONNECT) {
        await scheduleReconnect();
      }
      return;
    }
    consecutiveHeartbeatFailures = 0;
  } catch {
    consecutiveHeartbeatFailures += 1;
    log('❌ Heartbeat: failed to get client state. Triggering reconnect.');
    if (!isReconnecting && !isInitializing && consecutiveHeartbeatFailures >= HEARTBEAT_FAILURES_BEFORE_RECONNECT) {
      await scheduleReconnect();
    }
    return;
  }

  const sinceMsg = status.lastMessageAt ? now - status.lastMessageAt : null;
  if (sinceMsg !== null) {
    log(`⏳ Heartbeat: last message ${(sinceMsg / 1000).toFixed(0)}s ago`);
  }

  writeStatus({});
}, HEARTBEAT_MS);

/* ===========================
   Startup & shutdown
=========================== */
async function start() {
  writeStatus({
    state: 'starting',
    details: 'Initializing client…',
    needsQr: false,
    lastError: null,
    humanMessage: 'Initializing WhatsApp client…'
  });

  setupEventHandlers(client);
  setupCallHandlers(client);
  startHTTPServer();

  isInitializing = true;

  try {
    await client.initialize();
  } catch (err: any) {
    console.error('⚠️ Initial init failed:', {
      message: err?.message,
      stack: err?.stack,
      name: err?.name,
      timestamp: new Date().toISOString()
    });

    // If init froze or WhatsApp Web never loaded → restart
    writeStatus({
      state: 'error',
      details: `Init failed: ${err?.message || err}`,
      lastError: err?.message || 'Init failed',
      humanMessage: 'Initialization failed; attempting to reconnect...'
    });
    await scheduleReconnect();
    return;
  } finally {
    isInitializing = false;
  }
}

async function shutdown(reason = 'signal') {
  if (shuttingDown) return;
  shuttingDown = true;
  writeStatus({
    state: 'shutting_down',
    details: `Received termination (${reason})`,
  });
  if (reconnectTimer) clearTimeout(reconnectTimer);
  try {
    await safeDestroy();
  } catch (err: any) {
    log(`⚠️ Error during client destroy: ${err?.message || err}`);
  }
  try {
    if (httpServer) {
      httpServer.close?.();
    }
  } catch (err: any) {
    log(`⚠️ Error during HTTP server close: ${err?.message || err}`);
  }
  setTimeout(() => process.exit(0), 0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

start();
