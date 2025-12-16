// db/db.ts - Simple JSON-based storage to avoid native module issues
import fs from "fs";
import path from "path";

// Ensure output directory exists
const OUT_DIR = path.join(process.cwd(), "out");
if (!fs.existsSync(OUT_DIR)) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
}

// Simple in-memory storage with file persistence
interface Message {
  id: string;
  chatId: string;
  senderId: string;
  displayName: string;
  savedName?: string | null;
  pushname?: string | null;
  fromMe: boolean;
  type: string;
  body: string | null;
  ts: number;
  mimetype?: string | null;
  filename?: string | null;
  filesize?: number | null;
  durationMs?: number | null;
}

interface Call {
  id: string;
  chatId: string;
  callerId: string;
  calleeId?: string;
  isVideo: boolean;
  isGroup: boolean;
  timestamp: number;
  durationMs?: number;
  status: string;
  endTimestamp?: number;
}

interface Chat {
  id: string;
  name: string;
  isGroup: boolean;
  archived: boolean;
  lastMessageTs?: number;
  messageCount?: number;
}

interface Contact {
  id: string;
  savedName?: string | null;
  pushname?: string | null;
  displayName: string;
}

class SimpleDB {
  private messages: Map<string, Message> = new Map();
  private calls: Map<string, Call> = new Map();
  private chats: Map<string, Chat> = new Map();
  private contacts: Map<string, Contact> = new Map();

  private messagesFile = path.join(OUT_DIR, "messages.json");
  private callsFile = path.join(OUT_DIR, "calls.json");
  private chatsFile = path.join(OUT_DIR, "chats.json");
  private contactsFile = path.join(OUT_DIR, "contacts.json");

  constructor() {
    this.loadFromFiles();
  }

  private loadFromFiles() {
    try {
      // Load messages
      if (fs.existsSync(this.messagesFile)) {
        const data = fs.readFileSync(this.messagesFile, 'utf8');
        const messages = JSON.parse(data);
        Object.entries(messages).forEach(([id, msg]) => {
          this.messages.set(id, msg as Message);
        });
      }

      // Load calls
      if (fs.existsSync(this.callsFile)) {
        const data = fs.readFileSync(this.callsFile, 'utf8');
        const calls = JSON.parse(data);
        Object.entries(calls).forEach(([id, call]) => {
          this.calls.set(id, call as Call);
        });
      }

      // Load chats
      if (fs.existsSync(this.chatsFile)) {
        const data = fs.readFileSync(this.chatsFile, 'utf8');
        const chats = JSON.parse(data);
        Object.entries(chats).forEach(([id, chat]) => {
          this.chats.set(id, chat as Chat);
        });
      }

      // Load contacts
      if (fs.existsSync(this.contactsFile)) {
        const data = fs.readFileSync(this.contactsFile, 'utf8');
        const contacts = JSON.parse(data);
        Object.entries(contacts).forEach(([id, contact]) => {
          this.contacts.set(id, contact as Contact);
        });
      }

      console.log("✅ Data loaded from files");
    } catch (error) {
      console.log("Creating new database files...");
    }
  }

  private saveToFiles() {
    try {
      // Save messages
      const messagesObj = Object.fromEntries(this.messages);
      fs.writeFileSync(this.messagesFile, JSON.stringify(messagesObj, null, 2));

      // Save calls
      const callsObj = Object.fromEntries(this.calls);
      fs.writeFileSync(this.callsFile, JSON.stringify(callsObj, null, 2));

      // Save chats
      const chatsObj = Object.fromEntries(this.chats);
      fs.writeFileSync(this.chatsFile, JSON.stringify(chatsObj, null, 2));

      // Save contacts
      const contactsObj = Object.fromEntries(this.contacts);
      fs.writeFileSync(this.contactsFile, JSON.stringify(contactsObj, null, 2));
    } catch (error) {
      console.error("Failed to save to files:", error);
    }
  }

  // Message operations
  saveMessage(message: Message) {
    this.messages.set(message.id, message);

    // Update chat
    const existingChat = this.chats.get(message.chatId);
    const updatedChat: Chat = {
      ...(existingChat || {}),
      id: message.chatId,
      name: existingChat?.name || message.chatId,
      isGroup: existingChat?.isGroup || false,
      archived: existingChat?.archived || false,
      lastMessageTs: existingChat?.lastMessageTs
        ? Math.max(existingChat.lastMessageTs, message.ts)
        : message.ts,
      messageCount: (existingChat?.messageCount || 0) + 1
    };
    this.chats.set(message.chatId, updatedChat);

    // Update contact
    if (message.senderId !== 'me') {
      const existing = this.contacts.get(message.senderId);
      const displayNameCandidate =
        (message.displayName && message.displayName !== message.senderId
          ? message.displayName
          : undefined) ??
        existing?.displayName;

      const displayName =
        displayNameCandidate ||
        message.savedName ||
        message.pushname ||
        existing?.savedName ||
        existing?.pushname ||
        message.senderId;

      const savedName = message.savedName ?? existing?.savedName ?? null;
      const pushname = message.pushname ?? existing?.pushname ?? null;

      this.contacts.set(message.senderId, {
        id: message.senderId,
        displayName,
        savedName,
        pushname
      });
    }

    this.saveToFiles();
  }

  hasMessage(id: string): boolean {
    return this.messages.has(id);
  }

  getMessagesByChat(chatId: string, limit = 50): Message[] {
    return Array.from(this.messages.values())
      .filter(msg => msg.chatId === chatId)
      .sort((a, b) => b.ts - a.ts)
      .slice(0, limit)
      .reverse();
  }

  getMessageCount(chatId: string): number {
    let count = 0;
    for (const msg of this.messages.values()) {
      if (msg.chatId === chatId) count += 1;
    }
    return count;
  }

  getLatestMessage(chatId: string): Message | undefined {
    let latest: Message | undefined;
    for (const msg of this.messages.values()) {
      if (msg.chatId !== chatId) continue;
      if (!latest || msg.ts > latest.ts) latest = msg;
    }
    return latest;
  }

  getOldestMessage(chatId: string): Message | undefined {
    let oldest: Message | undefined;
    for (const msg of this.messages.values()) {
      if (msg.chatId !== chatId) continue;
      if (!oldest || msg.ts < oldest.ts) oldest = msg;
    }
    return oldest;
  }

  getMessageCountSince(chatId: string, sinceTs: number): number {
    let count = 0;
    for (const msg of this.messages.values()) {
      if (msg.chatId === chatId && msg.ts >= sinceTs) count += 1;
    }
    return count;
  }

  getRecentTextMessages(chatId: string, limit = 30): Message[] {
    return Array.from(this.messages.values())
      .filter(msg => msg.chatId === chatId && msg.type === "chat" && typeof msg.body === "string")
      .sort((a, b) => b.ts - a.ts)
      .slice(0, limit);
  }

  getMessagesByChatSince(chatId: string, sinceTs: number, limit = 2000): Message[] {
    const res: Message[] = [];
    for (const msg of this.messages.values()) {
      if (msg.chatId !== chatId) continue;
      if (msg.ts < sinceTs) continue;
      res.push(msg);
    }
    res.sort((a, b) => a.ts - b.ts); // oldest-first
    return res.slice(0, limit);
  }

  getRecentMessages(limit = 100): Message[] {
    return Array.from(this.messages.values())
      .sort((a, b) => b.ts - a.ts)
      .slice(0, limit)
      .reverse();
  }

  getMessagesSince(ts: number, limit: number): { messages: Message[]; total: number; hasMore: boolean } {
    const hardLimit = Math.min(Math.max(limit || 0, 1), 5000);
    const filtered = Array.from(this.messages.values()).filter(m => m.ts >= ts);
    filtered.sort((a, b) => a.ts - b.ts); // oldest-first
    const total = filtered.length;
    const messages = filtered.slice(0, hardLimit);
    const hasMore = total > messages.length;
    return { messages, total, hasMore };
  }

  getMessagesBefore(ts: number, limit: number): { messages: Message[]; total: number; hasMore: boolean } {
    const hardLimit = Math.min(Math.max(limit || 0, 1), 5000);
    const filtered = Array.from(this.messages.values()).filter(m => m.ts < ts);
    filtered.sort((a, b) => b.ts - a.ts); // newest-first for backward paging
    const total = filtered.length;
    const messages = filtered.slice(0, hardLimit);
    const hasMore = total > messages.length;
    return { messages, total, hasMore };
  }

  // Call operations
  saveCall(call: Call) {
    this.calls.set(call.id, call);
    this.saveToFiles();
  }

  getRecentCalls(limit = 50): Call[] {
    return Array.from(this.calls.values())
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit)
      .reverse();
  }

  // Chat operations
  getChats(): Chat[] {
    return Array.from(this.chats.values());
  }
  updateChatName(chatId: string, name: string) {
    const existing = this.chats.get(chatId);
    if (!existing) return;
    this.chats.set(chatId, { ...existing, name });
    this.saveToFiles();
  }

  // Contact operations
  getContacts(): Contact[] {
    return Array.from(this.contacts.values());
  }
  updateContact(contact: Contact) {
    this.contacts.set(contact.id, contact);
    this.saveToFiles();
  }

  // Get database stats
  getStats() {
    return {
      messages: this.messages.size,
      calls: this.calls.size,
      chats: this.chats.size,
      contacts: this.contacts.size
    };
  }
}

// Create database instance
export const db = new SimpleDB();

// Initialize function (no-op for this simple implementation)
export function initDb() {
  console.log("✅ Simple JSON database initialized");
  console.log("📊 Database stats:", db.getStats());
}

// Export the class for external use if needed
export { SimpleDB };
