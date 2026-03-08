CREATE TABLE public.suppression_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_type text NOT NULL,
  value text NOT NULL,
  description text,
  is_active boolean NOT NULL DEFAULT true,
  suppressed_count integer NOT NULL DEFAULT 0,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE public.suppression_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable read access for all users" ON public.suppression_rules FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.suppression_rules FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.suppression_rules FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.suppression_rules FOR DELETE USING (true);

CREATE TRIGGER update_suppression_rules_updated_at
  BEFORE UPDATE ON public.suppression_rules
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();