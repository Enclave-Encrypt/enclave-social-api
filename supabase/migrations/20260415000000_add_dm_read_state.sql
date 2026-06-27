-- Track when each user last read each DM conversation
CREATE TABLE IF NOT EXISTS dm_read_state (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  other_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  last_read_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, other_user_id)
);

ALTER TABLE dm_read_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage their own DM read state"
  ON dm_read_state
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Enable realtime so read state syncs live across devices
ALTER PUBLICATION supabase_realtime ADD TABLE dm_read_state;

-- Returns unread DM counts per sender for the calling user
CREATE OR REPLACE FUNCTION get_dm_unread_counts()
RETURNS TABLE(other_user_id UUID, unread_count BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT
    dm.sender_id AS other_user_id,
    COUNT(*)::BIGINT AS unread_count
  FROM direct_messages dm
  LEFT JOIN dm_read_state drs
    ON drs.other_user_id = dm.sender_id
    AND drs.user_id = auth.uid()
  WHERE
    dm.recipient_id = auth.uid()
    AND (drs.last_read_at IS NULL OR dm.created_at > drs.last_read_at)
  GROUP BY dm.sender_id
  HAVING COUNT(*) > 0;
$$;
