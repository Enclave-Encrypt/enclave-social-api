ALTER TABLE users
  ADD COLUMN IF NOT EXISTS app_theme TEXT NOT NULL DEFAULT 'default',
  ADD COLUMN IF NOT EXISTS theme_blur_strength INTEGER NOT NULL DEFAULT 10;

ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_app_theme_check;

ALTER TABLE users
  ADD CONSTRAINT users_app_theme_check
  CHECK (app_theme IN ('default', 'native_frosted', 'clear', 'hakerman'));

ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_theme_blur_strength_check;

ALTER TABLE users
  ADD CONSTRAINT users_theme_blur_strength_check
  CHECK (theme_blur_strength >= 0 AND theme_blur_strength <= 18);
