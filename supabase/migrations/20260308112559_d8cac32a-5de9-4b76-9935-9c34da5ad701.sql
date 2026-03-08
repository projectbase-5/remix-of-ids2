
-- hunt_results table
CREATE TABLE public.hunt_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  hunt_type text NOT NULL,
  source_ip text NOT NULL,
  target text NOT NULL,
  score numeric NOT NULL DEFAULT 0,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.hunt_results ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read access for all users" ON public.hunt_results FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.hunt_results FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable delete access for all users" ON public.hunt_results FOR DELETE USING (true);

-- host_risk_scores table
CREATE TABLE public.host_risk_scores (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address text NOT NULL UNIQUE,
  hostname text,
  alert_score integer NOT NULL DEFAULT 0,
  anomaly_score integer NOT NULL DEFAULT 0,
  reputation_score integer NOT NULL DEFAULT 0,
  asset_multiplier numeric NOT NULL DEFAULT 1.0,
  total_risk integer NOT NULL DEFAULT 0,
  risk_level text NOT NULL DEFAULT 'low',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.host_risk_scores ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read access for all users" ON public.host_risk_scores FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.host_risk_scores FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.host_risk_scores FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.host_risk_scores FOR DELETE USING (true);

CREATE TRIGGER update_host_risk_scores_updated_at
  BEFORE UPDATE ON public.host_risk_scores
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
