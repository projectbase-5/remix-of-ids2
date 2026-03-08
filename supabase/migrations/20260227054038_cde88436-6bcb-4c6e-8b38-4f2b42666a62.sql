-- Create flow_metrics_log table for persisting flow summaries
CREATE TABLE public.flow_metrics_log (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  source_ip text NOT NULL,
  total_packets integer NOT NULL DEFAULT 0,
  total_bytes bigint NOT NULL DEFAULT 0,
  unique_destinations integer NOT NULL DEFAULT 0,
  unique_ports integer NOT NULL DEFAULT 0,
  active_flows integer NOT NULL DEFAULT 0
);

-- Enable RLS
ALTER TABLE public.flow_metrics_log ENABLE ROW LEVEL SECURITY;

-- Public read/insert (agent writes, dashboard reads)
CREATE POLICY "Allow public insert on flow_metrics_log"
  ON public.flow_metrics_log FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Allow public read on flow_metrics_log"
  ON public.flow_metrics_log FOR SELECT
  USING (true);