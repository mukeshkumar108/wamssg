CREATE TABLE `chats` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text,
	`is_group` integer DEFAULT false NOT NULL,
	`archived` integer DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE `contacts` (
	`id` text PRIMARY KEY NOT NULL,
	`saved_name` text,
	`pushname` text,
	`display_name` text
);
--> statement-breakpoint
CREATE TABLE `messages` (
	`id` text PRIMARY KEY NOT NULL,
	`chat_id` text NOT NULL,
	`sender_id` text,
	`saved_name` text,
	`pushname` text,
	`display_name` text,
	`participant_id` text,
	`participant_name` text,
	`from_me` integer NOT NULL,
	`type` text NOT NULL,
	`body` text,
	`ts` integer NOT NULL,
	`mimetype` text,
	`filename` text,
	`filesize` integer,
	`duration_ms` integer
);
--> statement-breakpoint
CREATE TABLE `reactions` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`message_id` text NOT NULL,
	`emoji` text NOT NULL,
	`sender_id` text
);
