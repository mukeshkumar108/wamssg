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
    if (!this.chats.has(message.chatId)) {
      this.chats.set(message.chatId, {
        id: message.chatId,
        name: message.chatId,
        isGroup: false,
        archived: false
      });
    }

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

  getMessagesByChat(chatId: string, limit = 50): Message[] {
    return Array.from(this.messages.values())
      .filter(msg => msg.chatId === chatId)
      .sort((a, b) => b.ts - a.ts)
      .slice(0, limit)
      .reverse();
  }

  getRecentMessages(limit = 100): Message[] {
    return Array.from(this.messages.values())
      .sort((a, b) => b.ts - a.ts)
      .slice(0, limit)
      .reverse();
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

  // Contact operations
  getContacts(): Contact[] {
    return Array.from(this.contacts.values());
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
