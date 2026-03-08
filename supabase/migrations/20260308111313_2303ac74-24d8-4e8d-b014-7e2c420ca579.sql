
-- Create asset_inventory table
CREATE TABLE public.asset_inventory (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address text NOT NULL,
  hostname text,
  device_type text NOT NULL DEFAULT 'unknown',
  os text,
  owner text,
  department text,
  criticality text NOT NULL DEFAULT 'medium',
  is_active boolean NOT NULL DEFAULT true,
  last_seen timestamptz NOT NULL DEFAULT now(),
  first_seen timestamptz NOT NULL DEFAULT now(),
  mac_address text,
  open_ports jsonb NOT NULL DEFAULT '[]'::jsonb,
  services jsonb NOT NULL DEFAULT '[]'::jsonb,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Unique index on ip_address
CREATE UNIQUE INDEX idx_asset_inventory_ip ON public.asset_inventory (ip_address);

-- Enable RLS
ALTER TABLE public.asset_inventory ENABLE ROW LEVEL SECURITY;

-- RLS policies (public access matching project pattern)
CREATE POLICY "Enable read access for all users" ON public.asset_inventory FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.asset_inventory FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.asset_inventory FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.asset_inventory FOR DELETE USING (true);

-- Auto-update updated_at
CREATE TRIGGER update_asset_inventory_updated_at
  BEFORE UPDATE ON public.asset_inventory
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();
