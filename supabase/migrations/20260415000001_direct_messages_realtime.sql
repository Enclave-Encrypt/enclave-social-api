-- Enable realtime for direct_messages.
-- REPLICA IDENTITY FULL is required so Supabase realtime can broadcast
-- row changes to the correct subscribers when RLS is in play.
ALTER TABLE direct_messages REPLICA IDENTITY FULL;

-- Safely add to the realtime publication (no-op if already present).
DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE direct_messages;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;
