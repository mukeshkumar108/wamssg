// drizzle.config.ts
import type { Config } from "drizzle-kit";

export default {
  schema: "./db/schema.ts",
  out: "./drizzle/migrations",
  dialect: "sqlite",                    // tells Drizzle we're on SQLite
  dbCredentials: {
    url: "./out/messages.db",           // path to your SQLite file
  },
} satisfies Config;
