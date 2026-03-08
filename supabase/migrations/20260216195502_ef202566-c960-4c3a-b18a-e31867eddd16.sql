CREATE TABLE public.live_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_type text NOT NULL,
  severity text NOT NULL DEFAULT 'medium',
  source_ip text NOT NULL,
  destination_ip text,
  description text NOT NULL,
  detection_module text NOT NULL,
  metadata jsonb DEFAULT '{}'::jsonb,
  status text DEFAULT 'active',
  dedupe_key text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE public.live_alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read" ON public.live_alerts FOR SELECT USING (true);
CREATE POLICY "Allow public insert" ON public.live_alerts FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update" ON public.live_alerts FOR UPDATE USING (true);