-- One-time migration to bring an existing D1 database up to the CURRENT
-- ad_requests shape (name, phone, subject, qualification, area, photo_url,
-- pay_sender, pay_trx, pay_amount, note, status, created_at, updated_at).
--
-- Since this project is still mid-development (no real approved tutors to
-- protect yet), the simplest and safest path is to just drop whatever old
-- request table you have and let the Worker/schema.sql recreate it fresh.
--
-- STEP 1 — drop whichever old table exists (only ONE of these will succeed;
-- the other will fail with "no such table", which is fine, ignore it):
DROP TABLE IF EXISTS tutor_requests;
DROP TABLE IF EXISTS ad_requests;

-- STEP 2 — recreate it in the current shape:
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

-- Apply with:
--   npx wrangler d1 execute kushtia-smart-tutor-db --file=./migrate-ad-requests.sql
--   npx wrangler d1 execute kushtia-smart-tutor-db --file=./migrate-ad-requests.sql --remote   (for production)
--
-- If you DO have real ad-request rows you care about keeping, tell me and
-- I'll write an ALTER-TABLE-based version that preserves existing rows
-- instead of dropping the table.
