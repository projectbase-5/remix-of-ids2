/**
 * execute-response — Supabase Edge Function
 * ============================================
 * Executes and logs automated response actions (block IP, notify, isolate host).
 * Actions are logged to `response_actions` table for audit trail.
 *
 * In production, each action_type would integrate with real infrastructure
 * (firewall API, SIEM, EDR, etc.). Currently logs the action as executed.
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

interface ActionRequest {
  action_type: string;
  target_ip?: string;
  target_host?: string;
  parameters?: Record<string, unknown>;
  incident_id?: string;
  scored_incident_id?: string;
  triggered_by?: string;
}

const SUPPORTED_ACTIONS: Record<string, { description: string; handler: (req: ActionRequest) => Promise<Record<string, unknown>> }> = {
  block_ip: {
    description: "Block an IP address at the firewall level",
    handler: async (req) => {
      // In production: call firewall API (iptables, AWS WAF, Cloudflare, etc.)
      console.log(`[RESPONSE] Blocking IP: ${req.target_ip}`);
      return {
        action: "block_ip",
        ip: req.target_ip,
        firewall_rule_id: `fw-${Date.now()}`,
        message: `IP ${req.target_ip} blocked successfully`,
        simulated: true,
      };
    },
  },
  unblock_ip: {
    description: "Remove an IP block from the firewall",
    handler: async (req) => {
      console.log(`[RESPONSE] Unblocking IP: ${req.target_ip}`);
      return {
        action: "unblock_ip",
        ip: req.target_ip,
        message: `IP ${req.target_ip} unblocked successfully`,
        simulated: true,
      };
    },
  },
  isolate_host: {
    description: "Isolate a host from the network (quarantine)",
    handler: async (req) => {
      console.log(`[RESPONSE] Isolating host: ${req.target_host || req.target_ip}`);
      return {
        action: "isolate_host",
        host: req.target_host || req.target_ip,
        quarantine_id: `qr-${Date.now()}`,
        message: `Host ${req.target_host || req.target_ip} isolated from network`,
        simulated: true,
      };
    },
  },
  send_notification: {
    description: "Send alert notification to SOC team",
    handler: async (req) => {
      const channel = req.parameters?.channel || "default";
      console.log(`[RESPONSE] Sending notification to channel: ${channel}`);
      return {
        action: "send_notification",
        channel,
        message: `Notification sent to ${channel}`,
        simulated: true,
      };
    },
  },
  rate_limit: {
    description: "Apply rate limiting to a source IP",
    handler: async (req) => {
      const limit = req.parameters?.requests_per_minute || 10;
      console.log(`[RESPONSE] Rate limiting ${req.target_ip} to ${limit} req/min`);
      return {
        action: "rate_limit",
        ip: req.target_ip,
        limit,
        message: `Rate limit applied: ${req.target_ip} → ${limit} req/min`,
        simulated: true,
      };
    },
  },
  capture_forensics: {
    description: "Capture forensic data (memory dump, network capture)",
    handler: async (req) => {
      console.log(`[RESPONSE] Capturing forensics for ${req.target_host || req.target_ip}`);
      return {
        action: "capture_forensics",
        target: req.target_host || req.target_ip,
        capture_id: `cap-${Date.now()}`,
        message: `Forensic capture initiated for ${req.target_host || req.target_ip}`,
        simulated: true,
      };
    },
  },
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const body: ActionRequest = await req.json();

    // Validate action type
    if (!body.action_type || !SUPPORTED_ACTIONS[body.action_type]) {
      return new Response(
        JSON.stringify({
          error: `Unsupported action: ${body.action_type}`,
          supported_actions: Object.keys(SUPPORTED_ACTIONS).map(k => ({
            type: k,
            description: SUPPORTED_ACTIONS[k].description,
          })),
        }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Create the action record as pending
    const { data: actionRecord, error: insertError } = await supabase
      .from("response_actions")
      .insert({
        action_type: body.action_type,
        target_ip: body.target_ip || null,
        target_host: body.target_host || null,
        parameters: body.parameters || {},
        incident_id: body.incident_id || null,
        scored_incident_id: body.scored_incident_id || null,
        triggered_by: body.triggered_by || "dashboard",
        status: "executing",
      })
      .select("id")
      .single();

    if (insertError) {
      console.error("Error creating action record:", insertError);
      throw insertError;
    }

    // Execute the action
    let result: Record<string, unknown>;
    let status: string;

    try {
      result = await SUPPORTED_ACTIONS[body.action_type].handler(body);
      status = "completed";
    } catch (execErr) {
      result = { error: (execErr as Error).message };
      status = "failed";
    }

    // Update the action record with result
    await supabase
      .from("response_actions")
      .update({
        status,
        result,
        completed_at: new Date().toISOString(),
      })
      .eq("id", actionRecord.id);

    return new Response(
      JSON.stringify({
        success: status === "completed",
        action_id: actionRecord.id,
        action_type: body.action_type,
        status,
        result,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    console.error("Execute response error:", err);
    return new Response(
      JSON.stringify({ error: (err as Error).message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
