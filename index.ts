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

const { Client, LocalAuth } = WAWebJS as any;

/* ===========================
   Config
=========================== */
const OUTPUT_DIR = path.join(process.cwd(), 'out');
const RAW_PATH = path.join(OUTPUT_DIR, 'raw.jsonl');
const STATUS_PATH = path.join(OUTPUT_DIR, 'status.json');
const AUTH_DIR = path.join(process.cwd(), '.wwebjs_auth');

const BOOTSTRAP_CHAT_LIMIT = +(process.env.BOOTSTRAP_CHAT_LIMIT || 15);
const BOOTSTRAP_MSG_LIMIT  = +(process.env.BOOTSTRAP_MSG_LIMIT  || 20);

const HEARTBEAT_MS   = +(process.env.HEARTBEAT_MS || 30_000);
const MAX_RETRIES_BEFORE_AUTH_RESET = +(process.env.MAX_RETRIES_BEFORE_AUTH_RESET || 5);
const BASE_RETRY_MS  = +(process.env.BASE_RETRY_MS || 5_000);
const MAX_RETRY_MS   = +(process.env.MAX_RETRY_MS || 60_000);

const LOG_PATH = path.join(OUTPUT_DIR, 'service.log');
const LOG_MAX_BYTES = +(process.env.LOG_MAX_BYTES || 10_000_000); // 10 MB
const LOG_KEEP = +(process.env.LOG_KEEP || 3); // keep service.log.1 .. .3
const BACKFILL_BATCH = +(process.env.BACKFILL_BATCH || 100);

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
};

function writeStatus(partial: Partial<typeof status>) {
  Object.assign(status, partial);
  try {
    fs.writeFileSync(
      STATUS_PATH,
      JSON.stringify({ ...status, now: Date.now() }, null, 2),
      'utf8'
    );
  } catch {}
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
      databaseSize: dbSize,
      callsCaptured: activeCalls.size,
      version: '1.0.0',
      timestamp: Date.now()
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
  app.get('/api/messages/recent-chats', authenticate, async (req, res) => {
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

  app.get('/api/messages/chat/:chatId', authenticate, async (req, res) => {
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

  app.get('/api/messages/contact/:contactId', authenticate, async (req, res) => {
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

  app.get('/api/messages/recent', authenticate, async (req, res) => {
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

  app.get('/api/messages/since', authenticate, async (req, res) => {
    try {
      const ts = parseInt(req.query.ts as string);
      if (!ts || isNaN(ts)) {
        return res.status(400).json({ error: 'Invalid timestamp parameter' });
      }

      // Use SimpleDB methods
      const allMessages = (db as any).getRecentMessages(1000) || [];
      const filteredMessages = allMessages.filter((msg: any) => msg.ts >= ts);

      res.json({
        messages: filteredMessages, // Already in correct order (oldest first)
        total: filteredMessages.length,
        since: ts
      });
    } catch (err: any) {
      log('❌ API Error /api/messages/since:', err?.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // API Routes - Calls
  app.get('/api/calls/recent', authenticate, async (req, res) => {
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

  app.get('/api/calls/since', authenticate, async (req, res) => {
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

  let displayName = chatName || notifyName || senderId;
  if (savedName && savedName !== senderId) {
    displayName = savedName;
  } else if (resolvedNames.displayName && resolvedNames.displayName !== senderId) {
    // Next: whatever resolveContactName thought was best
    displayName = resolvedNames.displayName;
  } else if (chatName) {
    displayName = chatName;
  } else if (notifyName) {
    displayName = notifyName;
  }

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

  log(`💬 New message in ${chat.name || displayName}`);
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
    for (const m of messages) {
      await saveMessage(m, chat);
    }
  }
  log('💾 Saved messages to raw.jsonl and database');
}

/* ===========================
   Smart Backfill worker
=========================== */
async function smartBackfill() {
  try {
    log(`🔄 Smart Backfill: scanning recent chats for backfill opportunities…`);
    const chats: Chat[] = await client.getChats();

    // Only process recent chats (top 20) to avoid memory issues
    const recentChats = chats
      .filter((c: Chat) => resolvedChatName(c) !== 'WhatsApp')
      .slice(0, 20);

    let processedCount = 0;
    const maxChatsPerRun = 3; // Process max 3 chats per backfill run

    for (const chat of recentChats) {
      if (processedCount >= maxChatsPerRun) {
        log(`🔄 Backfill: pausing after ${processedCount} chats (memory management)`);
        break;
      }

      try {
        // Check how many messages we already have for this chat
        const existingMessages = (db as any).getMessagesByChat(chat.id._serialized, 100000) || [];
        const existingCount = existingMessages.length;

        // Only backfill if we have very few messages (<50) to avoid memory spikes
        if (existingCount < 50) {
          log(
            `📥 Backfilling up to ${BACKFILL_BATCH} messages for ${resolvedChatName(
              chat
            )} (${existingCount} existing messages)`
          );

          const msgs = await chat.fetchMessages({ limit: BACKFILL_BATCH });

          for (const m of msgs) {
            await saveMessage(m, chat);
          }

          processedCount++;

          // Small delay between chats to prevent memory buildup
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      } catch (chatErr: any) {
        log(`⚠️ Skipping chat ${resolvedChatName(chat)} due to error: ${chatErr?.message}`);
        continue;
      }
    }

    if (processedCount > 0) {
      log(`✅ Smart backfill complete: processed ${processedCount} chats`);
    } else {
      log(`🔄 Smart backfill: no chats needed backfill (all have sufficient messages)`);
    }
  } catch (err: any) {
    console.error("❌ Smart backfill error:", {
      message: err?.message,
      stack: err?.stack,
      name: err?.name,
      timestamp: new Date().toISOString()
    });
  }
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

  // Daily run: every 24h ±30m jitter
  const DAY_MS = 24 * 60 * 60 * 1000;
  setInterval(() => {
    const jitter = (Math.random() - 0.5) * 60 * 60 * 1000; // ±30m
    const delay = Math.max(0, DAY_MS + jitter);

    log(`🕒 Scheduling daily smart backfill with jitter (${(delay/60000).toFixed(0)}m)...`);
    setTimeout(() => {
      smartBackfill();
    }, delay);
  }, DAY_MS);
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
    writeStatus({ state: 'connected', lastReadyAt: Date.now(), details: '' });
    log('✅ WhatsApp client is ready!');
    try {
      await bootstrap();
      scheduleSmartBackfill();
      // No more immediate backfill - smart backfill starts after 15 minutes
    } catch (err: any) {
      writeStatus({
        state: 'error',
        details: `Bootstrap failed: ${err?.message || err}`,
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
    writeStatus({ state: 'reconnecting', details: `Disconnected: ${reason}` });
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

async function safeDestroy() {
  try {
    await client.destroy();
  } catch {}
}

async function scheduleReconnect() {
  if (shuttingDown) return;
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
        });
        try {
          fs.rmSync(AUTH_DIR, { recursive: true, force: true });
        } catch {}
        status.retryCount = 0;
      }

      await client.initialize();
    } catch (err: any) {
      console.error('⚠️ Init failed:', {
        message: err?.message,
        stack: err?.stack,
        name: err?.name,
        timestamp: new Date().toISOString()
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

  if (!hasEverBeenReady) return;
  if (isInitializing) {
    log('⏳ Heartbeat: init in progress; skipping state check.');
    return;
  }

  try {
    const s = await client.getState();
    if (s !== 'CONNECTED') {
      log(`⚠️ Heartbeat: client state = ${s}. Triggering reconnect.`);
      if (!isReconnecting) {
        await scheduleReconnect();
      }
      return;
    }
  } catch {
    log('❌ Heartbeat: failed to get client state. Triggering reconnect.');
    if (!isReconnecting) {
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
  writeStatus({ state: 'starting', details: 'Initializing client…' });

  setupEventHandlers(client);
  setupCallHandlers(client);
  startHTTPServer();

  isInitializing = true;

  const initPromise = client.initialize();
  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("InitTimeout")), 60000) // 60s startup watchdog
  );

  try {
    await Promise.race([initPromise, timeoutPromise]);
  } catch (err: any) {
    console.error('⚠️ Initial init failed:', {
      message: err?.message,
      stack: err?.stack,
      name: err?.name,
      timestamp: new Date().toISOString()
    });

    // If init froze or WhatsApp Web never loaded → restart
    isInitializing = false;
    await scheduleReconnect();
    return;
  } finally {
    if (isInitializing) isInitializing = false;
  }
}

async function shutdown() {
  shuttingDown = true;
  writeStatus({
    state: 'shutting_down',
    details: 'Received termination signal',
  });
  if (reconnectTimer) clearTimeout(reconnectTimer);
  try {
    await safeDestroy();
  } catch {}
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

start();
