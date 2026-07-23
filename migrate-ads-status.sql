-- Kushtia Smart Tutor — migrate ad_requests.status to the new lifecycle
-- ('pending','running','paused','rejected','cancelled').
--
-- Only run this if your D1 already has an ad_requests table created from
-- the OLD schema (CHECK status IN ('pending','approved','rejected')).
-- If you're deploying fresh, just run schema.sql — you don't need this file.
--
-- Apply with:
--   npx wrangler d1 execute kushtia-smart-tutor-db --file=./migrate-ads-status.sql --remote
--
-- SQLite can't ALTER a CHECK constraint in place, so this rebuilds the table:
--   1. create a new table with the new constraint
--   2. copy rows across, mapping old 'approved' -> new 'running'
--   3. drop the old table and rename the new one into place

CREATE TABLE ad_requests_new (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id),
  status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'paused', 'rejected', 'cancelled')),
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

INSERT INTO ad_requests_new
SELECT
  id, user_id,
  CASE status WHEN 'approved' THEN 'running' ELSE status END,
  name, phone, subject, qualification, area, photo_url,
  pay_sender, pay_trx, pay_amount, note, created_at, updated_at
FROM ad_requests;

DROP TABLE ad_requests;
ALTER TABLE ad_requests_new RENAME TO ad_requests;

CREATE INDEX IF NOT EXISTS idx_ad_requests_status ON ad_requests(status);
CREATE INDEX IF NOT EXISTS idx_ad_requests_user ON ad_requests(user_id);
