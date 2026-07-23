-- Migration: Tutor Profile Upgrade
-- Adds new columns to ad_requests for the full tutor-profile system.
-- Safe to run on the existing table: every column is added with NULL or a
-- sensible default, so old rows and old code paths keep working untouched.
--
-- Run this once against your D1 database, e.g.:
--   wrangler d1 execute <YOUR_DB_NAME> --remote --file=./migration_001_tutor_profile.sql
-- (drop --remote to test locally first)

-- ---------- Identity / basic info ----------
ALTER TABLE ad_requests ADD COLUMN gender TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN university TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN department TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN session TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN tutor_id TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN current_location TEXT DEFAULT '';

-- ---------- Tuition preferences ----------
ALTER TABLE ad_requests ADD COLUMN expected_salary TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN experience_years TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN availability TEXT DEFAULT 'available';
ALTER TABLE ad_requests ADD COLUMN subjects TEXT DEFAULT '';

-- ---------- Education: Bachelor's (current university) ----------
ALTER TABLE ad_requests ADD COLUMN edu_bachelor_dept TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN edu_bachelor_session TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN edu_bachelor_current INTEGER DEFAULT 0;

-- ---------- Education: SSC ----------
ALTER TABLE ad_requests ADD COLUMN ssc_year TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN ssc_school TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN ssc_group TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN ssc_result TEXT DEFAULT '';

-- ---------- Education: HSC ----------
ALTER TABLE ad_requests ADD COLUMN hsc_year TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN hsc_college TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN hsc_group TEXT DEFAULT '';
ALTER TABLE ad_requests ADD COLUMN hsc_result TEXT DEFAULT '';

-- ---------- Extra / bio ----------
ALTER TABLE ad_requests ADD COLUMN extra_info TEXT DEFAULT '';

-- ---------- Tutor ID auto-generation bookkeeping ----------
-- Keeps a running per-university serial counter so tutor_id (e.g. RU_1240)
-- can be generated deterministically the first time an ad is approved.
CREATE TABLE IF NOT EXISTS tutor_id_counters (
  prefix TEXT PRIMARY KEY,   -- e.g. 'RU'
  last_serial INTEGER NOT NULL DEFAULT 1239   -- next generated will be 1240
);
