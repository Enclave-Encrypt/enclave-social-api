-- Track when each user last read each channel
CREATE TABLE IF NOT EXISTS channel_read_state (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  channel_id TEXT NOT NULL,
  last_read_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, channel_id)
);

ALTER TABLE channel_read_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage their own read state"
  ON channel_read_state
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Enable realtime so read state syncs live across devices
ALTER PUBLICATION supabase_realtime ADD TABLE channel_read_state;

-- Returns unread message counts per channel for the calling user
CREATE OR REPLACE FUNCTION get_unread_counts(p_channel_ids TEXT[])
RETURNS TABLE(channel_id TEXT, unread_count BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT
    m.channel_id::TEXT,
    COUNT(*)::BIGINT AS unread_count
  FROM messages m
  LEFT JOIN channel_read_state crs
    ON crs.channel_id = m.channel_id::TEXT
    AND crs.user_id = auth.uid()
  WHERE
    m.channel_id::TEXT = ANY(p_channel_ids)
    AND m.sender_id != auth.uid()
    AND (crs.last_read_at IS NULL OR m.created_at > crs.last_read_at)
  GROUP BY m.channel_id
  HAVING COUNT(*) > 0;
$$;
