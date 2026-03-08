
-- Table for real captured network traffic from the Python sniffer
CREATE TABLE public.network_traffic (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  source_ip text NOT NULL,
  destination_ip text NOT NULL,
  protocol text NOT NULL DEFAULT 'TCP',
  port integer DEFAULT 0,
  packet_size integer DEFAULT 0,
  flags jsonb DEFAULT '[]'::jsonb,
  payload_preview text,
  is_suspicious boolean DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Table for real system metrics from the Python agent
CREATE TABLE public.system_metrics_log (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  cpu_usage numeric NOT NULL DEFAULT 0,
  memory_usage numeric NOT NULL DEFAULT 0,
  disk_usage numeric NOT NULL DEFAULT 0,
  network_health numeric NOT NULL DEFAULT 100,
  active_connections integer DEFAULT 0,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.network_traffic ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_metrics_log ENABLE ROW LEVEL SECURITY;

-- Public read for dashboard
CREATE POLICY "Allow public read on network_traffic"
  ON public.network_traffic FOR SELECT USING (true);

CREATE POLICY "Allow public insert on network_traffic"
  ON public.network_traffic FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public read on system_metrics_log"
  ON public.system_metrics_log FOR SELECT USING (true);

CREATE POLICY "Allow public insert on system_metrics_log"
  ON public.system_metrics_log FOR INSERT WITH CHECK (true);

-- Index for polling by time
CREATE INDEX idx_network_traffic_created_at ON public.network_traffic (created_at DESC);
CREATE INDEX idx_system_metrics_log_created_at ON public.system_metrics_log (created_at DESC);
