
CREATE TABLE public.attack_timelines (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_ip text NOT NULL,
  timeline_events jsonb NOT NULL DEFAULT '[]'::jsonb,
  kill_chain_phases jsonb NOT NULL DEFAULT '[]'::jsonb,
  total_events integer NOT NULL DEFAULT 0,
  first_event_at timestamptz,
  last_event_at timestamptz,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.attack_timelines ADD CONSTRAINT attack_timelines_source_ip_key UNIQUE (source_ip);

ALTER TABLE public.attack_timelines ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read access for all users" ON public.attack_timelines FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.attack_timelines FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.attack_timelines FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.attack_timelines FOR DELETE USING (true);

CREATE TRIGGER update_attack_timelines_updated_at
  BEFORE UPDATE ON public.attack_timelines
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
