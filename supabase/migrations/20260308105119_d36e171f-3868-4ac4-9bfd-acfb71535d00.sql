-- Create correlation_groups table to persist detected attack chains
CREATE TABLE public.correlation_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_ip text NOT NULL,
  composite_score integer NOT NULL DEFAULT 0,
  phases jsonb NOT NULL DEFAULT '[]'::jsonb,
  is_multi_stage boolean NOT NULL DEFAULT false,
  escalated boolean NOT NULL DEFAULT false,
  first_seen timestamp with time zone NOT NULL,
  last_seen timestamp with time zone NOT NULL,
  sequence_pattern text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Create correlation_events table to link events to groups
CREATE TABLE public.correlation_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id uuid NOT NULL REFERENCES public.correlation_groups(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  event_id uuid NOT NULL,
  timestamp timestamp with time zone NOT NULL,
  attack_type text NOT NULL,
  phase text NOT NULL,
  threat_score integer NOT NULL DEFAULT 50,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Add indexes for efficient querying
CREATE INDEX idx_correlation_groups_source_ip ON public.correlation_groups(source_ip);
CREATE INDEX idx_correlation_groups_created_at ON public.correlation_groups(created_at DESC);
CREATE INDEX idx_correlation_groups_escalated ON public.correlation_groups(escalated) WHERE escalated = true;
CREATE INDEX idx_correlation_events_group_id ON public.correlation_events(group_id);
CREATE INDEX idx_correlation_events_timestamp ON public.correlation_events(timestamp DESC);

-- Enable RLS
ALTER TABLE public.correlation_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.correlation_events ENABLE ROW LEVEL SECURITY;

-- RLS policies for correlation_groups
CREATE POLICY "Enable read access for all users" ON public.correlation_groups FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.correlation_groups FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.correlation_groups FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.correlation_groups FOR DELETE USING (true);

-- RLS policies for correlation_events
CREATE POLICY "Enable read access for all users" ON public.correlation_events FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.correlation_events FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable delete access for all users" ON public.correlation_events FOR DELETE USING (true);

-- Update trigger for correlation_groups
CREATE TRIGGER update_correlation_groups_updated_at
  BEFORE UPDATE ON public.correlation_groups
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();