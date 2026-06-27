-- Drop the overly-permissive INSERT and UPDATE policies that only checked
-- bucket_id, allowing any authenticated user to overwrite any server's icon.
DROP POLICY IF EXISTS "Authenticated users can upload server icons" ON storage.objects;
DROP POLICY IF EXISTS "Server owners can update their icons" ON storage.objects;

-- INSERT: only the server owner may upload to that server's folder.
-- Path convention: {serverId}/icon.{ext}
-- (storage.foldername(name))[1] extracts the first path segment (the server id).
CREATE POLICY "Server owners can upload their icons"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'server-icons'
  AND (storage.foldername(name))[1] IN (
    SELECT id::text FROM public.servers WHERE owner_id = auth.uid()
  )
);

-- UPDATE: same ownership requirement, applied to both the existing row (USING)
-- and the replacement row (WITH CHECK) to prevent path-swap attacks.
CREATE POLICY "Server owners can update their icons"
ON storage.objects FOR UPDATE
TO authenticated
USING (
  bucket_id = 'server-icons'
  AND (storage.foldername(name))[1] IN (
    SELECT id::text FROM public.servers WHERE owner_id = auth.uid()
  )
)
WITH CHECK (
  bucket_id = 'server-icons'
  AND (storage.foldername(name))[1] IN (
    SELECT id::text FROM public.servers WHERE owner_id = auth.uid()
  )
);

-- DELETE: server owners may remove their own icons.
CREATE POLICY "Server owners can delete their icons"
ON storage.objects FOR DELETE
TO authenticated
USING (
  bucket_id = 'server-icons'
  AND (storage.foldername(name))[1] IN (
    SELECT id::text FROM public.servers WHERE owner_id = auth.uid()
  )
);
