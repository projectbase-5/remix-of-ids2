
CREATE TABLE public.notification_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  config_type TEXT NOT NULL,
  target TEXT NOT NULL,
  severity_threshold TEXT NOT NULL DEFAULT 'critical',
  is_active BOOLEAN DEFAULT true,
  last_sent_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.notification_configs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read access for all users" ON public.notification_configs FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.notification_configs FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.notification_configs FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.notification_configs FOR DELETE USING (true);

CREATE INDEX idx_notification_configs_active ON public.notification_configs (config_type, is_active);

CREATE TRIGGER update_notification_configs_updated_at
BEFORE UPDATE ON public.notification_configs
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();
