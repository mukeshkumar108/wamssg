// types.d.ts
import 'whatsapp-web.js';

declare module 'whatsapp-web.js' {
  // --- Extend Chat type ---
  interface ChatId {
    _serialized: string;
    server?: string;
    user?: string;
    _serialized?: string;
  }

  interface Chat {
    id: ChatId;  // not just string anymore
    name?: string;
    formattedTitle?: string;
    isReadOnly?: boolean;
    archived?: boolean;
    isGroup?: boolean;
  }

  // --- Extend Message type ---
  interface Message {
    _data?: {
      notifyName?: string;
      mimetype?: string;
      filename?: string;
      size?: number;
      duration?: number;
    };

    type?: string; // 'chat' | 'image' | 'video' | 'audio' | 'sticker' | 'document' | 'unknown'
    author?: string; // participant ID if group

    reactions?: Array<{
      id: string;       // WhatsApp's reaction ID
      text: string;     // the emoji 👍❤️😂
      serializedId?: string; // full unique ID (we’ll add this ourselves)
      senderId?: string;     // who reacted
    }>;

    // --- Our enriched fields (for JSONL/DB) ---
    senderId?: string;
    senderName?: string;
    mediaMeta?: {
      type: string;     // sticker, image, video, etc.
      mimetype?: string;
      filename?: string | null;
      filesize?: number | null;
      durationMs?: number | null;
    } | null;
  }
}
