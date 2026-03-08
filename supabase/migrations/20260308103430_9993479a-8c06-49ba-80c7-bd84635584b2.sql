-- Allow updating predictions (for analyst feedback on actual_label)
CREATE POLICY "Allow public update on predictions"
ON public.predictions
FOR UPDATE
USING (true)
WITH CHECK (true);