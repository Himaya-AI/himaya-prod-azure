-- Migration: add hit_count to policies table
-- Tracks how many times each policy has been triggered

ALTER TABLE policies ADD COLUMN IF NOT EXISTS hit_count INTEGER DEFAULT 0 NOT NULL;
