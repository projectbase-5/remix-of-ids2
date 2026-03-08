-- Response actions audit log table
CREATE TABLE public.response_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id uuid REFERENCES public.incident_logs(id) ON DELETE SET NULL,
  scored_incident_id uuid REFERENCES public.scored_incidents(id) ON DELETE SET NULL,
  action_type text NOT NULL,
  target_ip text,
  target_host text,
  parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'pending',
  result jsonb,
  triggered_by text NOT NULL DEFAULT 'system',
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE INDEX idx_response_actions_incident ON public.response_actions(incident_id);
CREATE INDEX idx_response_actions_scored ON public.response_actions(scored_incident_id);
CREATE INDEX idx_response_actions_status ON public.response_actions(status);

ALTER TABLE public.response_actions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read on response_actions"
  ON public.response_actions FOR SELECT USING (true);

CREATE POLICY "Allow public insert on response_actions"
  ON public.response_actions FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public update on response_actions"
  ON public.response_actions FOR UPDATE USING (true);