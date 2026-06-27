-- Add age range and NSFW settings to users table
CREATE TYPE age_range_type AS ENUM ('under_13', '13_17', '18_plus');

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS age_range age_range_type,
  ADD COLUMN IF NOT EXISTS nsfw_enabled BOOLEAN NOT NULL DEFAULT FALSE;
