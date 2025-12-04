CREATE TABLE `calls` (
	`id` text PRIMARY KEY NOT NULL,
	`chat_id` text NOT NULL,
	`caller_id` text NOT NULL,
	`callee_id` text,
	`is_video` integer NOT NULL,
	`is_group` integer DEFAULT false NOT NULL,
	`timestamp` integer NOT NULL,
	`duration_ms` integer,
	`status` text NOT NULL,
	`end_timestamp` integer
);
