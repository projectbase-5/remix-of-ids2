/**
 * ingest-traffic — Supabase Edge Function
 * =========================================
 * Accepts batched payloads from the Python IDS agent containing:
 *   • packets[]      — raw network traffic rows
 *   • alerts[]       — agent-side detections (port scan, DoS, etc.)
 *   • system_metrics  — CPU, memory, disk, network health
 *
 * Authentication: The agent must include `api_key` in the JSON body.
 * This value is compared against the `AGENT_API_KEY` secret stored in
 * Supabase.  JWT verification is disabled for this function so the
 * agent can call it without a Supabase user session.
 *
 * Server-side backup detection:
 *   After inserting packets the function also runs lightweight detection
 *   on the batch itself (port scan: 10+ unique ports, DoS: 50+ packets).
 *   This acts as a safety net in case the Python agent's detectors miss
 *   something or are not running.
 *
 * Alert deduplication:
 *   Each alert carries an optional `dedupe_key`. Before inserting, the
 *   function checks if a row with that key already exists in `live_alerts`.
 *   This prevents duplicates from both the agent and the server-side
 *   detector writing the same alert.
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

interface AlertPayload {
  alert_type: string;
  severity: string;
  source_ip: string;
  destination_ip?: string;
  description: string;
  detection_module: string;
  metadata?: Record<string, unknown>;
  dedupe_key?: string;
}

Deno.serve(async (req) => {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body = await req.json();

    // ------------------------------------------------------------------
    // Authentication: validate the shared secret (AGENT_API_KEY).
    // The agent sends this as `body.api_key`.
    // ------------------------------------------------------------------
    const agentKey = Deno.env.get("AGENT_API_KEY");

    if (!agentKey || body.api_key !== agentKey) {
      return new Response(
        JSON.stringify({ error: "Unauthorized: invalid api_key" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Service-role client — bypasses RLS for server-side writes
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const results: Record<string, unknown> = {};

    // ==================================================================
    // 1. Insert raw packets into `network_traffic`
    // ==================================================================
    if (body.packets && Array.isArray(body.packets) && body.packets.length > 0) {
      const rows = body.packets.map((p: Record<string, unknown>) => ({
        source_ip: p.source_ip || "0.0.0.0",
        destination_ip: p.destination_ip || "0.0.0.0",
        protocol: p.protocol || "TCP",
        port: p.port || 0,
        packet_size: p.packet_size || 0,
        flags: p.flags || [],
        payload_preview: p.payload_preview || null,
        is_suspicious: p.is_suspicious || false,
      }));

      const { data, error } = await supabase
        .from("network_traffic")
        .insert(rows)
        .select("id");

      if (error) {
        console.error("Error inserting packets:", error);
        results.packets_error = error.message;
      } else {
        results.packets_inserted = data?.length || 0;
      }

      // ================================================================
      // 2. Server-side backup detection on the incoming batch
      // ================================================================
      const serverAlerts: AlertPayload[] = [];

      // --- Port scan detection ---
      // If a single source IP contacts 10+ unique destination ports in
      // this batch, flag it as a port scan.
      const portsBySource: Record<string, Set<number>> = {};
      for (const p of body.packets) {
        const src = p.source_ip || "0.0.0.0";
        if (!portsBySource[src]) portsBySource[src] = new Set();
        if (p.port) portsBySource[src].add(p.port);
      }
      for (const [src, ports] of Object.entries(portsBySource)) {
        if (ports.size >= 10) {
          // Minute-granularity window key for deduplication
          const now = Math.floor(Date.now() / 60000);
          serverAlerts.push({
            alert_type: "Port Scan",
            severity: "high",
            source_ip: src,
            description: `Server-side detection: ${src} contacted ${ports.size} unique ports in a single batch`,
            detection_module: "edge_function_port_scan",
            dedupe_key: `edge_portscan_${src}_${now}`,
          });
        }
      }

      // --- DoS / flooding detection ---
      // If a single source IP sends 50+ packets in one batch, flag it.
      const countBySource: Record<string, number> = {};
      for (const p of body.packets) {
        const src = p.source_ip || "0.0.0.0";
        countBySource[src] = (countBySource[src] || 0) + 1;
      }
      for (const [src, count] of Object.entries(countBySource)) {
        if (count >= 50) {
          const now = Math.floor(Date.now() / 60000);
          serverAlerts.push({
            alert_type: "DoS",
            severity: "high",
            source_ip: src,
            description: `Server-side detection: ${src} sent ${count} packets in a single batch (possible flooding)`,
            detection_module: "edge_function_dos",
            dedupe_key: `edge_dos_${src}_${now}`,
          });
        }
      }

      // Insert any server-side alerts (with deduplication)
      if (serverAlerts.length > 0) {
        await insertAlerts(supabase, serverAlerts, results, "server_alerts");
      }
    }

    // ==================================================================
    // 3. Insert agent-reported alerts into `live_alerts`
    // ==================================================================
    if (body.alerts && Array.isArray(body.alerts) && body.alerts.length > 0) {
      await insertAlerts(supabase, body.alerts, results, "agent_alerts");
    }

    // ==================================================================
    // 4. Insert system metrics snapshot into `system_metrics_log`
    // ==================================================================
    if (body.system_metrics) {
      const m = body.system_metrics;
      const { error } = await supabase.from("system_metrics_log").insert({
        cpu_usage: m.cpu_usage ?? 0,
        memory_usage: m.memory_usage ?? 0,
        disk_usage: m.disk_usage ?? 0,
        network_health: m.network_health ?? 100,
        active_connections: m.active_connections ?? 0,
      });

      if (error) {
        console.error("Error inserting metrics:", error);
        results.metrics_error = error.message;
      } else {
        results.metrics_inserted = true;
      }
    }

    // ==================================================================
    // 5. Insert flow summaries into `flow_metrics_log`
    // ==================================================================
    if (body.flow_summaries && Array.isArray(body.flow_summaries) && body.flow_summaries.length > 0) {
      const flowRows = body.flow_summaries.map((f: Record<string, unknown>) => ({
        source_ip: f.source_ip || "0.0.0.0",
        total_packets: f.total_packets || 0,
        total_bytes: f.total_bytes || 0,
        unique_destinations: f.unique_destinations || 0,
        unique_ports: f.unique_ports || 0,
        active_flows: f.active_flows || 0,
      }));

      const { error } = await supabase
        .from("flow_metrics_log")
        .insert(flowRows);

      if (error) {
        console.error("Error inserting flow summaries:", error);
        results.flow_summaries_error = error.message;
      } else {
        results.flow_summaries_inserted = flowRows.length;
      }
    }

    // ==================================================================
    // 6. Upsert assets into `asset_inventory`
    // ==================================================================
    if (body.assets && Array.isArray(body.assets) && body.assets.length > 0) {
      let assetsUpserted = 0;
      for (const asset of body.assets) {
        const { error } = await supabase
          .from("asset_inventory")
          .upsert(
            {
              ip_address: asset.ip_address,
              device_type: asset.device_type || "unknown",
              os: asset.os || null,
              open_ports: asset.open_ports || [],
              services: asset.services || [],
              last_seen: asset.last_seen
                ? new Date(asset.last_seen * 1000).toISOString()
                : new Date().toISOString(),
            },
            { onConflict: "ip_address" }
          );
        if (error) {
          console.error("Error upserting asset:", error);
          results.assets_error = error.message;
        } else {
          assetsUpserted++;
        }
      }
      results.assets_upserted = assetsUpserted;
    }

    // ==================================================================
    // 7. Upsert scored incidents from agent-side scoring engine
    // ==================================================================
    if (body.incidents && Array.isArray(body.incidents) && body.incidents.length > 0) {
      let incidentsInserted = 0;
      for (const inc of body.incidents) {
        // Check for existing open incident for this IP
        const { data: existing } = await supabase
          .from("scored_incidents")
          .select("id, alert_ids")
          .eq("source_ip", inc.source_ip)
          .eq("status", "open")
          .limit(1);

        if (existing && existing.length > 0) {
          await supabase
            .from("scored_incidents")
            .update({
              total_score: inc.total_score,
              alert_count: inc.alert_count,
              attack_types: inc.attack_types,
              severity: inc.severity,
              first_alert_at: inc.first_alert_at ? new Date(inc.first_alert_at * 1000).toISOString() : new Date().toISOString(),
              last_alert_at: inc.last_alert_at ? new Date(inc.last_alert_at * 1000).toISOString() : new Date().toISOString(),
              sequence_pattern: inc.sequence_pattern || null,
            })
            .eq("id", existing[0].id);
        } else {
          await supabase.from("scored_incidents").insert({
            source_ip: inc.source_ip,
            total_score: inc.total_score,
            alert_count: inc.alert_count,
            attack_types: inc.attack_types || [],
            severity: inc.severity || "low",
            first_alert_at: inc.first_alert_at ? new Date(inc.first_alert_at * 1000).toISOString() : new Date().toISOString(),
            last_alert_at: inc.last_alert_at ? new Date(inc.last_alert_at * 1000).toISOString() : new Date().toISOString(),
            sequence_pattern: inc.sequence_pattern || null,
            status: inc.status || "open",
            alert_ids: inc.alert_ids || [],
          });
        }
        incidentsInserted++;
      }
      results.incidents_inserted = incidentsInserted;
    }

    return new Response(JSON.stringify({ success: true, ...results }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("Ingest error:", err);
    return new Response(
      JSON.stringify({ error: (err as Error).message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

/**
 * insertAlerts — Insert alerts into `live_alerts` with deduplication.
 *
 * For each alert that carries a `dedupe_key`, the function first checks
 * whether a row with that key already exists.  If it does, the alert is
 * skipped to avoid duplicates.  Alerts without a dedupe_key are always
 * inserted.
 *
 * @param supabase  - Supabase client (service role)
 * @param alerts    - Array of alert payloads to insert
 * @param results   - Mutable results object (written back to the caller)
 * @param resultKey - Key prefix for result counts (e.g. "server_alerts")
 */
async function insertAlerts(
  supabase: ReturnType<typeof createClient>,
  alerts: AlertPayload[],
  results: Record<string, unknown>,
  resultKey: string
) {
  let inserted = 0;
  let skipped = 0;

  for (const alert of alerts) {
    // --- Deduplication check ---
    if (alert.dedupe_key) {
      const { data: existing } = await supabase
        .from("live_alerts")
        .select("id")
        .eq("dedupe_key", alert.dedupe_key)
        .limit(1);

      if (existing && existing.length > 0) {
        skipped++;
        continue;
      }
    }

    const { data: insertedAlert, error } = await supabase.from("live_alerts").insert({
      alert_type: alert.alert_type,
      severity: alert.severity || "medium",
      source_ip: alert.source_ip,
      destination_ip: alert.destination_ip || null,
      description: alert.description,
      detection_module: alert.detection_module,
      metadata: alert.metadata || {},
      dedupe_key: alert.dedupe_key || null,
      status: "active",
    }).select("id, source_ip, destination_ip").maybeSingle();

    if (error) {
      console.error(`Error inserting alert:`, error);
      results[`${resultKey}_error`] = error.message;
    } else {
      inserted++;

      // Auto-enrich: check IP reputation for source IP in background
      if (insertedAlert?.source_ip) {
        enrichAlertInBackground(supabase, insertedAlert.id, insertedAlert.source_ip, insertedAlert.destination_ip);
      }
    }
  }

  results[`${resultKey}_inserted`] = inserted;
  results[`${resultKey}_skipped`] = skipped;
}

/**
 * Fire-and-forget enrichment: checks IP reputation and stores it in alert metadata.
 */
async function enrichAlertInBackground(
  supabase: ReturnType<typeof createClient>,
  alertId: string,
  sourceIp: string,
  destinationIp: string | null
) {
  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    // Call check-ip-reputation for source IP
    const srcResponse = await fetch(`${supabaseUrl}/functions/v1/check-ip-reputation`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${supabaseKey}`,
      },
      body: JSON.stringify({ ip_address: sourceIp }),
    });

    const enrichment: Record<string, unknown> = {};
    if (srcResponse.ok) {
      enrichment.source_reputation = await srcResponse.json();
    }

    // Check destination IP if available
    if (destinationIp) {
      const dstResponse = await fetch(`${supabaseUrl}/functions/v1/check-ip-reputation`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${supabaseKey}`,
        },
        body: JSON.stringify({ ip_address: destinationIp }),
      });
      if (dstResponse.ok) {
        enrichment.destination_reputation = await dstResponse.json();
      }
    }

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

    await supabase
      .from("live_alerts")
      .update({ metadata: enrichment })
      .eq("id", alertId);

    console.log(`Enriched alert ${alertId} with threat intel`);
  } catch (err) {
    console.error(`Failed to enrich alert ${alertId}:`, err);
  }
}
