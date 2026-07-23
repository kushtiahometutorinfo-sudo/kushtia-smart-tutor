-- Kushtia Smart Tutor — D1 schema
-- Apply with:
--   npx wrangler d1 execute kushtia-smart-tutor-db --file=./schema.sql
--   npx wrangler d1 execute kushtia-smart-tutor-db --file=./schema.sql --remote   (for production)
--
-- NOTE: this file uses CREATE TABLE IF NOT EXISTS, so it will NOT rename or
-- restructure a table that already exists on your DB from an older version
-- of this schema (either the original `tutor_requests` table, or an earlier
-- `ad_requests` table without the name/phone/photo/payment columns). If
-- you've deployed before, see migrate-ad-requests.sql for a one-time fix.

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

-- ad_requests: NOT part of registration/login anymore. A tutor account is
-- active the moment it's created, regardless of this table. A row here
-- represents the tutor's combined "list me publicly" request submitted from
-- profile.html — their display info, a photo URL (uploaded client-side to
-- Cloudinary, this table only stores the link), and their bKash/Nagad
-- payment proof, all in one go. Admin approves/rejects it independently of
-- login.
CREATE TABLE IF NOT EXISTS ad_requests (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id),
  status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  name           TEXT NOT NULL,
  phone          TEXT NOT NULL,
  subject        TEXT,
  qualification  TEXT,
  area           TEXT,
  photo_url      TEXT,
  pay_sender     TEXT,
  pay_trx        TEXT,
  pay_amount     TEXT,
  note           TEXT,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ad_requests_status ON ad_requests(status);
CREATE INDEX IF NOT EXISTS idx_ad_requests_user ON ad_requests(user_id);

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
