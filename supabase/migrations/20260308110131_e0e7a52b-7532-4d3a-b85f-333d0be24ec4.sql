-- Create scored_incidents table for aggregated incident scoring
CREATE TABLE public.scored_incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_ip text NOT NULL,
  total_score integer NOT NULL DEFAULT 0,
  alert_count integer NOT NULL DEFAULT 0,
  attack_types jsonb NOT NULL DEFAULT '[]'::jsonb,
  severity text NOT NULL DEFAULT 'low',
  first_alert_at timestamptz NOT NULL,
  last_alert_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'open',
  alert_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  sequence_pattern text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Create index for faster lookups
CREATE INDEX idx_scored_incidents_source_ip ON public.scored_incidents(source_ip);
CREATE INDEX idx_scored_incidents_status ON public.scored_incidents(status);
CREATE INDEX idx_scored_incidents_total_score ON public.scored_incidents(total_score DESC);

-- Enable RLS
ALTER TABLE public.scored_incidents ENABLE ROW LEVEL SECURITY;

-- RLS policies for scored_incidents
CREATE POLICY "Allow public read on scored_incidents"
  ON public.scored_incidents FOR SELECT
  USING (true);

CREATE POLICY "Allow public insert on scored_incidents"
  ON public.scored_incidents FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Allow public update on scored_incidents"
  ON public.scored_incidents FOR UPDATE
  USING (true);

CREATE POLICY "Allow public delete on scored_incidents"
  ON public.scored_incidents FOR DELETE
  USING (true);

-- Trigger to update updated_at
CREATE TRIGGER update_scored_incidents_updated_at
  BEFORE UPDATE ON public.scored_incidents
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();