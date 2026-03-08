/**
 * score-incidents — Supabase Edge Function
 * ==========================================
 * Aggregates recent `live_alerts` by source_ip within a configurable
 * time window and calculates a composite severity score.
 *
 * Scoring formula:
 *   base = Σ SEVERITY_WEIGHTS[alert.severity]
 *   diversity = unique_attack_types × 10
 *   sequence = has_kill_chain_sequence ? 30 : 0
 *   recency = alerts_in_last_5_min × 1.5 + alerts_in_last_15_min × 1.0
 *   total_score = base + diversity + sequence + recency
 *
 * Severity mapping:
 *   critical: score ≥ 100, high: score ≥ 60, medium: score ≥ 30, low: < 30
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

// Kill chain phases in order
const KILL_CHAIN_ORDER = [
  "reconnaissance",
  "delivery",
  "exploitation",
  "installation",
  "command_control",
  "exfiltration",
];

const ATTACK_TO_PHASE: Record<string, string> = {
  "Port Scan": "reconnaissance",
  "Network Scan": "reconnaissance",
  "Reconnaissance": "reconnaissance",
  "Brute Force": "exploitation",
  "SQL Injection": "exploitation",
  "XSS": "exploitation",
  "Exploit": "exploitation",
  "DoS": "delivery",
  "DDoS": "delivery",
  "Malware": "installation",
  "Trojan": "installation",
  "Ransomware": "installation",
  "C2 Communication": "command_control",
  "Beacon": "command_control",
  "DNS Anomaly": "command_control",
  "Data Exfiltration": "exfiltration",
  "Data Leak": "exfiltration",
};

function detectSequence(attackTypes: string[]): { hasSequence: boolean; pattern: string | null } {
  const phases = [...new Set(
    attackTypes
      .map((t) => ATTACK_TO_PHASE[t])
      .filter(Boolean)
  )];

  const phaseIndices = phases
    .map((p) => KILL_CHAIN_ORDER.indexOf(p))
    .filter((i) => i >= 0)
    .sort((a, b) => a - b);

  // Check for consecutive phases (at least 3 in sequence)
  let maxConsecutive = 1;
  let currentRun = 1;
  let seqStart = 0;

  for (let i = 1; i < phaseIndices.length; i++) {
    if (phaseIndices[i] - phaseIndices[i - 1] <= 1) {
      currentRun++;
      if (currentRun > maxConsecutive) {
        maxConsecutive = currentRun;
        seqStart = i - currentRun + 1;
      }
    } else {
      currentRun = 1;
    }
  }

  if (maxConsecutive >= 3) {
    const seqPhases = phaseIndices
      .slice(seqStart, seqStart + maxConsecutive)
      .map((i) => KILL_CHAIN_ORDER[i]);
    return { hasSequence: true, pattern: seqPhases.join(" → ") };
  }

  return { hasSequence: false, pattern: null };
}

function scoreSeverity(totalScore: number): string {
  if (totalScore >= 100) return "critical";
  if (totalScore >= 60) return "high";
  if (totalScore >= 30) return "medium";
  return "low";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const body = await req.json().catch(() => ({}));
    const windowMinutes = body.window_minutes || 60;
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();

    // Fetch recent active alerts within window
    const { data: alerts, error } = await supabase
      .from("live_alerts")
      .select("*")
      .gte("created_at", windowStart)
      .eq("status", "active")
      .order("created_at", { ascending: false })
      .limit(1000);

    if (error) throw error;
    if (!alerts || alerts.length === 0) {
      return new Response(
        JSON.stringify({ success: true, scored: 0, message: "No recent alerts to score" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Group alerts by source_ip
    const grouped: Record<string, typeof alerts> = {};
    for (const alert of alerts) {
      const ip = alert.source_ip;
      if (!grouped[ip]) grouped[ip] = [];
      grouped[ip].push(alert);
    }

    const now = Date.now();
    let scored = 0;

    for (const [sourceIp, ipAlerts] of Object.entries(grouped)) {
      // Base score from severity weights
      let base = 0;
      for (const a of ipAlerts) {
        base += SEVERITY_WEIGHTS[a.severity] || 3;
      }

      // Attack diversity bonus
      const attackTypes = [...new Set(ipAlerts.map((a) => a.alert_type))];
      const diversity = attackTypes.length * 10;

      // Sequence detection bonus
      const { hasSequence, pattern } = detectSequence(attackTypes);
      const sequenceBonus = hasSequence ? (attackTypes.length >= 4 ? 40 : 30) : 0;

      // Recency bonus
      let recency = 0;
      for (const a of ipAlerts) {
        const ageMs = now - new Date(a.created_at).getTime();
        if (ageMs < 5 * 60 * 1000) recency += 1.5;
        else if (ageMs < 15 * 60 * 1000) recency += 1.0;
        else recency += 0.5;
      }

      const totalScore = Math.round(base + diversity + sequenceBonus + recency);
      const severity = scoreSeverity(totalScore);
      const alertIds = ipAlerts.map((a) => a.id);

      const timestamps = ipAlerts.map((a) => new Date(a.created_at).getTime());
      const firstAlertAt = new Date(Math.min(...timestamps)).toISOString();
      const lastAlertAt = new Date(Math.max(...timestamps)).toISOString();

      // Check if there's already an open scored incident for this IP
      const { data: existing } = await supabase
        .from("scored_incidents")
        .select("id, alert_ids")
        .eq("source_ip", sourceIp)
        .eq("status", "open")
        .limit(1);

      if (existing && existing.length > 0) {
        // Merge alert_ids and update
        const existingIds = (existing[0].alert_ids as string[]) || [];
        const mergedIds = [...new Set([...existingIds, ...alertIds])];

        await supabase
          .from("scored_incidents")
          .update({
            total_score: totalScore,
            alert_count: mergedIds.length,
            attack_types: attackTypes,
            severity,
            first_alert_at: firstAlertAt,
            last_alert_at: lastAlertAt,
            alert_ids: mergedIds,
            sequence_pattern: pattern,
          })
          .eq("id", existing[0].id);
      } else {
        await supabase.from("scored_incidents").insert({
          source_ip: sourceIp,
          total_score: totalScore,
          alert_count: alertIds.length,
          attack_types: attackTypes,
          severity,
          first_alert_at: firstAlertAt,
          last_alert_at: lastAlertAt,
          alert_ids: alertIds,
          sequence_pattern: pattern,
          status: "open",
        });
      }

      scored++;
    }

    return new Response(
      JSON.stringify({ success: true, scored, total_alerts_processed: alerts.length }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    console.error("Score incidents error:", err);
    return new Response(
      JSON.stringify({ error: (err as Error).message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
