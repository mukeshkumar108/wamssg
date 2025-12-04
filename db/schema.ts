// db/schema.ts
import {
  sqliteTable, text, integer
} from 'drizzle-orm/sqlite-core';

// CHATS
export const chats = sqliteTable('chats', {
  id: text('id').primaryKey(),           // "5025...@c.us" or "...@g.us"
  name: text('name'),
  isGroup: integer('is_group', { mode: 'boolean' }).notNull().default(false),
  archived: integer('archived', { mode: 'boolean' }).notNull().default(false),
});

// CONTACTS
export const contacts = sqliteTable('contacts', {
  id: text('id').primaryKey(),
  savedName: text('saved_name'),        // phonebook name
  pushname: text('pushname'),           // WhatsApp profile name
  displayName: text('display_name'),    // savedName || pushname || id
});

// MESSAGES
export const messages = sqliteTable('messages', {
  id: text('id').primaryKey(),           // messageId
  chatId: text('chat_id').notNull(),

  senderId: text('sender_id'),

  // NEW: all names stored directly in message row
  savedName: text('saved_name'),
  pushname: text('pushname'),
  displayName: text('display_name'),

  participantId: text('participant_id'),
  participantName: text('participant_name'),

  fromMe: integer('from_me', { mode: 'boolean' }).notNull(),
  type: text('type').notNull(),
  body: text('body'),
  ts: integer('ts', { mode: 'number' }).notNull(),

  // media metadata
  mimetype: text('mimetype'),
  filename: text('filename'),
  filesize: integer('filesize', { mode: 'number' }),
  durationMs: integer('duration_ms', { mode: 'number' }),
});

// REACTIONS
export const reactions = sqliteTable('reactions', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  messageId: text('message_id').notNull(),
  emoji: text('emoji').notNull(),
  senderId: text('sender_id'),
});

// CALLS
export const calls = sqliteTable('calls', {
  id: text('id').primaryKey(),              // WhatsApp call ID
  chatId: text('chat_id').notNull(),         // Chat/group where call occurred
  callerId: text('caller_id').notNull(),     // Who initiated the call
  calleeId: text('callee_id'),               // Who was called (null for group calls)
  isVideo: integer('is_video', { mode: 'boolean' }).notNull(),
  isGroup: integer('is_group', { mode: 'boolean' }).notNull().default(false),
  timestamp: integer('timestamp', { mode: 'number' }).notNull(),  // Call start time
  durationMs: integer('duration_ms', { mode: 'number' }),         // Duration in milliseconds
  status: text('status').notNull(),          // 'pending', 'connecting', 'in_progress', 'ended', 'rejected', 'missed'
  endTimestamp: integer('end_timestamp', { mode: 'number' }),     // When call actually ended
});

// INDEXES for API performance
export const messageIndexes = {
  chatIdTs: 'CREATE INDEX IF NOT EXISTS idx_messages_chatId_ts ON messages(chatId, ts DESC)',
  senderIdTs: 'CREATE INDEX IF NOT EXISTS idx_messages_senderId_ts ON messages(senderId, ts DESC)',
  ts: 'CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts DESC)',
  type: 'CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(type)',
};

export const callIndexes = {
  timestamp: 'CREATE INDEX IF NOT EXISTS idx_calls_timestamp ON calls(timestamp DESC)',
  chatId: 'CREATE INDEX IF NOT EXISTS idx_calls_chatId ON calls(chatId)',
  callerId: 'CREATE INDEX IF NOT EXISTS idx_calls_callerId ON calls(callerId)',
};

export const chatIndexes = {
  isGroup: 'CREATE INDEX IF NOT EXISTS idx_chats_isGroup ON chats(isGroup)',
  archived: 'CREATE INDEX IF NOT EXISTS idx_chats_archived ON chats(archived)',
};
