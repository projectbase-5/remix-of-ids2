/**
 * cleanup-data — Supabase Edge Function
 * =======================================
 * Reads active retention policies from `retention_policies` table and
 * deletes rows older than the configured retention period.
 *
 * Authentication: AGENT_API_KEY in the JSON body.
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

// Tables that support cleanup (must have a created_at column)
const ALLOWED_TABLES = [
  "network_traffic",
  "system_metrics_log",
  "flow_metrics_log",
  "live_alerts",
  "incident_logs",
  "predictions",
  "network_topology",
  "correlation_events",
];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body = await req.json();

    // Auth check
    const agentKey = Deno.env.get("AGENT_API_KEY");
    // Allow service-role bearer token OR agent API key
    const authHeader = req.headers.get("authorization") || "";
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
    const isServiceAuth = authHeader === `Bearer ${serviceKey}`;

    if (!isServiceAuth && (!agentKey || body.api_key !== agentKey)) {
      return new Response(
        JSON.stringify({ error: "Unauthorized" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // Fetch active retention policies
    const { data: policies, error: policyError } = await supabase
      .from("retention_policies")
      .select("*")
      .eq("is_active", true);

    if (policyError) {
      console.error("Error fetching policies:", policyError);
      return new Response(
        JSON.stringify({ error: policyError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const details: Array<{ table: string; deleted: number; error?: string }> = [];
    let totalDeleted = 0;

    for (const policy of policies || []) {
      const tableName = policy.table_name;

      // Safety: only allow known tables
      if (!ALLOWED_TABLES.includes(tableName)) {
        details.push({ table: tableName, deleted: 0, error: "table not in allowlist" });
        continue;
      }

      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - policy.retention_days);
      const cutoffISO = cutoffDate.toISOString();

      try {
        // Count rows to delete
        const { count } = await supabase
          .from(tableName)
          .select("id", { count: "exact", head: true })
          .lt("created_at", cutoffISO);

        const rowCount = count || 0;

        if (rowCount > 0) {
          // Delete in batches of 1000
          let deleted = 0;
          while (deleted < rowCount) {
            const { data: batch } = await supabase
              .from(tableName)
              .select("id")
              .lt("created_at", cutoffISO)
              .limit(1000);

            if (!batch || batch.length === 0) break;

            const ids = batch.map((r: { id: string }) => r.id);
            const { error: delError } = await supabase
              .from(tableName)
              .delete()
              .in("id", ids);

            if (delError) {
              details.push({ table: tableName, deleted, error: delError.message });
              break;
            }

            deleted += batch.length;
          }

          totalDeleted += deleted;
          details.push({ table: tableName, deleted });

          // Update policy stats
          await supabase
            .from("retention_policies")
            .update({
              last_cleanup_at: new Date().toISOString(),
              rows_deleted: (policy.rows_deleted || 0) + deleted,
            })
            .eq("id", policy.id);
        } else {
          details.push({ table: tableName, deleted: 0 });
        }
      } catch (err) {
        console.error(`Cleanup error for ${tableName}:`, err);
        details.push({ table: tableName, deleted: 0, error: (err as Error).message });
      }
    }

    return new Response(
      JSON.stringify({ success: true, total_deleted: totalDeleted, details }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    console.error("Cleanup error:", err);
    return new Response(
      JSON.stringify({ error: (err as Error).message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
