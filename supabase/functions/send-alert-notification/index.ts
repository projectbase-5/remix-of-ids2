import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { Resend } from "npm:resend@2.0.0";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.56.1";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

interface AlertNotificationRequest {
  incident_type: string;
  severity: string;
  threat_score: number;
  source_ip?: string;
  destination_ip?: string;
  details?: Record<string, unknown>;
}

const handler = async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const payload: AlertNotificationRequest = await req.json();
    const { incident_type, severity, threat_score, source_ip, destination_ip, details } = payload;

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Fetch active notification configs
    const { data: configs } = await supabase
      .from("notification_configs")
      .select("*")
      .eq("is_active", true);

    if (!configs || configs.length === 0) {
      return new Response(JSON.stringify({ message: "No active notification configs" }), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    const results: { type: string; target: string; success: boolean; error?: string }[] = [];

    for (const config of configs) {
      // Check severity threshold
      const severityOrder = ["low", "medium", "high", "critical"];
      const configLevel = severityOrder.indexOf(config.severity_threshold);
      const incidentLevel = severityOrder.indexOf(severity);
      if (incidentLevel < configLevel) continue;

      if (config.config_type === "email") {
        const resendKey = Deno.env.get("RESEND_API_KEY");
        if (!resendKey) {
          results.push({ type: "email", target: config.target, success: false, error: "RESEND_API_KEY not configured" });
          continue;
        }

        try {
          const resend = new Resend(resendKey);
          await resend.emails.send({
            from: "IDS Alert <noreply@resend.dev>",
            to: [config.target],
            subject: `[${severity.toUpperCase()}] IDS Alert: ${incident_type} (Score: ${threat_score})`,
            html: `
              <h2>🚨 Security Alert - ${severity.toUpperCase()}</h2>
              <table style="border-collapse:collapse;width:100%">
                <tr><td style="padding:8px;border:1px solid #ddd"><strong>Incident Type</strong></td><td style="padding:8px;border:1px solid #ddd">${incident_type}</td></tr>
                <tr><td style="padding:8px;border:1px solid #ddd"><strong>Severity</strong></td><td style="padding:8px;border:1px solid #ddd">${severity}</td></tr>
                <tr><td style="padding:8px;border:1px solid #ddd"><strong>Threat Score</strong></td><td style="padding:8px;border:1px solid #ddd">${threat_score}/100</td></tr>
                ${source_ip ? `<tr><td style="padding:8px;border:1px solid #ddd"><strong>Source IP</strong></td><td style="padding:8px;border:1px solid #ddd">${source_ip}</td></tr>` : ""}
                ${destination_ip ? `<tr><td style="padding:8px;border:1px solid #ddd"><strong>Destination IP</strong></td><td style="padding:8px;border:1px solid #ddd">${destination_ip}</td></tr>` : ""}
              </table>
              <p style="margin-top:16px">Detected at ${new Date().toISOString()}</p>
              ${details ? `<pre style="background:#f4f4f4;padding:12px;border-radius:4px">${JSON.stringify(details, null, 2)}</pre>` : ""}
            `,
          });
          results.push({ type: "email", target: config.target, success: true });
        } catch (e) {
          results.push({ type: "email", target: config.target, success: false, error: String(e) });
        }
      } else if (config.config_type === "webhook") {
        try {
          const resp = await fetch(config.target, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              alert_type: "ids_detection",
              incident_type,
              severity,
              threat_score,
              source_ip,
              destination_ip,
              details,
              timestamp: new Date().toISOString(),
            }),
          });
          results.push({ type: "webhook", target: config.target, success: resp.ok, error: resp.ok ? undefined : `HTTP ${resp.status}` });
        } catch (e) {
          results.push({ type: "webhook", target: config.target, success: false, error: String(e) });
        }
      }

      // Update last_sent_at
      await supabase
        .from("notification_configs")
        .update({ last_sent_at: new Date().toISOString() })
        .eq("id", config.id);
    }

    return new Response(JSON.stringify({ results }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: String(error) }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
};

serve(handler);
