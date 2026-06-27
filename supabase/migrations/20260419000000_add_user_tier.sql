-- Add tier and stripe_customer_id to users table
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'bronze',
  ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;

UPDATE users
SET tier = 'bronze'
WHERE tier = 'free';

ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_tier_check;

ALTER TABLE users
  ADD CONSTRAINT users_tier_check
  CHECK (tier IN ('bronze', 'silver', 'gold', 'platinum'));

CREATE INDEX IF NOT EXISTS idx_users_stripe_customer_id
  ON users (stripe_customer_id)
  WHERE stripe_customer_id IS NOT NULL;
