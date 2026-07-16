CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  title TEXT,
  story_markdown TEXT NOT NULL,
  affection_rationale TEXT,
  share_text TEXT,
  journal_note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_trial_usage (
  user_id TEXT PRIMARY KEY,
  use_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS owner_credentials (
  email TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
