-- Add new columns for reworked server creation wizard
ALTER TABLE public.servers
  ADD COLUMN IF NOT EXISTS icon_url text,
  ADD COLUMN IF NOT EXISTS slow_mode_seconds integer DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS require_approval boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS subscription_description text;

-- Storage bucket for server icons
INSERT INTO storage.buckets (id, name, public)
VALUES ('server-icons', 'server-icons', true)
ON CONFLICT (id) DO NOTHING;

-- Allow authenticated users to upload their own server icons
DROP POLICY IF EXISTS "Authenticated users can upload server icons" ON storage.objects;
CREATE POLICY "Authenticated users can upload server icons"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'server-icons');

DROP POLICY IF EXISTS "Server icons are publicly readable" ON storage.objects;
CREATE POLICY "Server icons are publicly readable"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'server-icons');

DROP POLICY IF EXISTS "Server owners can update their icons" ON storage.objects;
CREATE POLICY "Server owners can update their icons"
ON storage.objects FOR UPDATE
TO authenticated
USING (bucket_id = 'server-icons');
