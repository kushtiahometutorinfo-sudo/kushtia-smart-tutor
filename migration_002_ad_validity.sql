-- Migration: Ad validity / auto-expiry
-- Adds columns to track how long an approved ad stays live, and a flag the
-- scheduled worker sets when it auto-pauses an expired ad (so the admin
-- panel can highlight "মেয়াদ শেষ — ডিলিট প্রয়োজন" rows).
--
-- Run once:
--   wrangler d1 execute <YOUR_DB_NAME> --remote --file=./migration_002_ad_validity.sql

ALTER TABLE ad_requests ADD COLUMN validity_days INTEGER DEFAULT 0;
ALTER TABLE ad_requests ADD COLUMN expires_at INTEGER DEFAULT NULL;   -- epoch ms, set on approve
ALTER TABLE ad_requests ADD COLUMN auto_expired INTEGER DEFAULT 0;    -- 1 = cron paused it for being past expires_at
