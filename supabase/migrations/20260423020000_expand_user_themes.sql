UPDATE users
SET app_theme = 'clear'
WHERE app_theme = 'custom_transparency';

ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_app_theme_check;

ALTER TABLE users
  ADD CONSTRAINT users_app_theme_check
  CHECK (app_theme IN ('default', 'native_frosted', 'clear', 'hakerman'));
