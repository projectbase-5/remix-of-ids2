
-- Network Topology table
CREATE TABLE public.network_topology (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  source_ip text NOT NULL,
  destination_ip text NOT NULL,
  connection_count integer NOT NULL DEFAULT 1,
  protocols jsonb NOT NULL DEFAULT '[]'::jsonb,
  bytes_transferred bigint NOT NULL DEFAULT 0,
  first_seen timestamp with time zone NOT NULL DEFAULT now(),
  last_seen timestamp with time zone NOT NULL DEFAULT now(),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  UNIQUE(source_ip, destination_ip)
);

ALTER TABLE public.network_topology ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read access for all users" ON public.network_topology FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.network_topology FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.network_topology FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.network_topology FOR DELETE USING (true);

-- Retention Policies table
CREATE TABLE public.retention_policies (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  table_name text NOT NULL UNIQUE,
  retention_days integer NOT NULL DEFAULT 30,
  archive_before_delete boolean NOT NULL DEFAULT false,
  is_active boolean NOT NULL DEFAULT true,
  last_cleanup_at timestamp with time zone,
  rows_deleted integer DEFAULT 0,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE public.retention_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read access for all users" ON public.retention_policies FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.retention_policies FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.retention_policies FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.retention_policies FOR DELETE USING (true);

-- Trigger for updated_at
CREATE TRIGGER update_network_topology_updated_at BEFORE UPDATE ON public.network_topology FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_retention_policies_updated_at BEFORE UPDATE ON public.retention_policies FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
