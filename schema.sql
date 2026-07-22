-- Kushtia Smart Tutor — D1 schema
-- Apply with:
--   npx wrangler d1 execute kushtia-smart-tutor-db --file=./schema.sql
--   npx wrangler d1 execute kushtia-smart-tutor-db --file=./schema.sql --remote   (for production)

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  phone         TEXT,
  email         TEXT,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('tutor', 'user')),
  created_at    INTEGER NOT NULL
);

-- phone/email must be unique when present, but both are nullable/optional
-- (signup allows either mobile or email as the primary identifier)
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL AND email != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone) WHERE phone IS NOT NULL AND phone != '';

CREATE TABLE IF NOT EXISTS tutor_requests (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id),
  status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  subject        TEXT,
  qualification  TEXT,
  area           TEXT,
  admin_note     TEXT,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tutor_requests_status ON tutor_requests(status);
CREATE INDEX IF NOT EXISTS idx_tutor_requests_user ON tutor_requests(user_id);

CREATE TABLE IF NOT EXISTS admins (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

-- NOTE: no admin row is seeded here on purpose, because the password needs to
-- go through the same PBKDF2 hashing the Worker uses (can't hand-write a
-- matching hash in SQL). Create the first admin using the one-time
-- POST /api/admin/bootstrap endpoint in worker/index.js instead — see the
-- comment above that handler for the exact curl command.
