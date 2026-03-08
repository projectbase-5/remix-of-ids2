import { createClient } from "https://esm.sh/@supabase/supabase-js@2.56.1";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { source_ip, destination_ip, alert_id } = await req.json();

    if (!source_ip && !alert_id) {
      return new Response(
        JSON.stringify({ error: 'source_ip or alert_id is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    let srcIp = source_ip;
    let dstIp = destination_ip;

    // If alert_id provided, fetch the alert to get IPs
    if (alert_id && !srcIp) {
      const { data: alert } = await supabase
        .from('live_alerts')
        .select('source_ip, destination_ip')
        .eq('id', alert_id)
        .maybeSingle();

      if (!alert) {
        return new Response(
          JSON.stringify({ error: 'Alert not found' }),
          { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
      srcIp = alert.source_ip;
      dstIp = alert.destination_ip;
    }

    // Check reputation for both IPs in parallel
    const enrichment: Record<string, unknown> = {};

    const checkIP = async (ip: string) => {
      const { data, error } = await supabase.functions.invoke('check-ip-reputation', {
        body: { ip_address: ip },
      });
      if (error) {
        console.error(`Error checking IP ${ip}:`, error);
        return null;
      }
      return data;
    };

    const promises: Promise<void>[] = [];

    if (srcIp) {
      promises.push(
        checkIP(srcIp).then(result => {
          if (result) enrichment.source_reputation = result;
        })
      );
    }

    if (dstIp) {
      promises.push(
        checkIP(dstIp).then(result => {
          if (result) enrichment.destination_reputation = result;
        })
      );
    }

    await Promise.all(promises);

    // Build summary
    const srcRep = enrichment.source_reputation as Record<string, unknown> | undefined;
    const dstRep = enrichment.destination_reputation as Record<string, unknown> | undefined;

    enrichment.summary = {
      source_malicious: srcRep?.is_malicious || false,
      destination_malicious: dstRep?.is_malicious || false,
      max_threat_score: Math.max(
        (srcRep?.reputation_score as number) || 0,
        (dstRep?.reputation_score as number) || 0
      ),
      enriched_at: new Date().toISOString(),
    };

    // If alert_id was provided, update the alert metadata with enrichment
    if (alert_id) {
      const { error: updateError } = await supabase
        .from('live_alerts')
        .update({
          metadata: enrichment,
        })
        .eq('id', alert_id);

      if (updateError) {
        console.error('Error updating alert metadata:', updateError);
      }
    }

    return new Response(JSON.stringify(enrichment), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Error in enrich-alert:', error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
