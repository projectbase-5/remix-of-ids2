/**
 * useNetworkFeatureExtractor — Real feature extraction from network_traffic data
 * ==============================================================================
 * Converts actual NetworkEvent objects into ML feature vectors using sliding
 * window aggregation over recent events, instead of random/hardcoded values.
 */

import { useCallback, useRef } from 'react';
import { NetworkEvent } from './useIDSDataStore';
import { MLFeatures } from './useMLPipeline';

// Port → service mapping
const PORT_SERVICE_MAP: Record<number, string> = {
  80: 'http', 443: 'http', 8080: 'http', 8443: 'http',
  21: 'ftp', 20: 'ftp',
  25: 'smtp', 587: 'smtp', 465: 'smtp',
  22: 'ssh',
  23: 'telnet',
};

// Derive TCP flag category from flags array
function deriveFlag(flags: string[]): string {
  if (!flags || flags.length === 0) return 'SF';
  const f = new Set(flags.map(s => s.toUpperCase()));
  if (f.has('RST') && f.has('SYN')) return 'RSTR';
  if (f.has('RST')) return 'REJ';
  if (f.has('SYN') && !f.has('ACK')) return 'S0';
  if (f.has('SH') || (f.has('SYN') && f.has('FIN'))) return 'SH';
  return 'SF';
}

export interface NetworkTrafficRow {
  id: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  port: number | null;
  packet_size: number | null;
  flags: any;
  payload_preview?: string | null;
  is_suspicious?: boolean | null;
  created_at: string;
}

/**
 * Convert a network_traffic DB row into MLFeatures
 */
export function extractFeaturesFromTrafficRow(
  row: NetworkTrafficRow,
  recentRows: NetworkTrafficRow[]
): MLFeatures {
  const port = row.port || 0;
  const packetSize = row.packet_size || 0;
  const flags: string[] = Array.isArray(row.flags) ? row.flags : [];
  const protocol = row.protocol?.toLowerCase() || 'tcp';
  const service = PORT_SERVICE_MAP[port] || 'other';
  const flag = deriveFlag(flags);

  // Sliding window aggregates (last 100 events within ~2s)
  const windowMs = 2000;
  const rowTime = new Date(row.created_at).getTime();
  const window = recentRows.filter(r => {
    const t = new Date(r.created_at).getTime();
    return t >= rowTime - windowMs && t <= rowTime;
  });

  const sameDstEvents = window.filter(r => r.destination_ip === row.destination_ip);
  const sameSrvEvents = sameDstEvents.filter(r => (r.port || 0) === port);
  const sameProtocolEvents = window.filter(r => r.protocol?.toLowerCase() === protocol);

  const count = sameDstEvents.length || 1;
  const srvCount = sameSrvEvents.length || 1;

  // Error rates based on flags
  const synOnlyCount = sameDstEvents.filter(r => {
    const f = Array.isArray(r.flags) ? r.flags.map((s: string) => s.toUpperCase()) : [];
    return f.includes('SYN') && !f.includes('ACK');
  }).length;
  const rstCount = sameDstEvents.filter(r => {
    const f = Array.isArray(r.flags) ? r.flags.map((s: string) => s.toUpperCase()) : [];
    return f.includes('RST');
  }).length;

  const serrorRate = count > 0 ? synOnlyCount / count : 0;
  const rerrorRate = count > 0 ? rstCount / count : 0;
  const sameSrvRate = count > 0 ? srvCount / count : 1;
  const diffSrvRate = 1 - sameSrvRate;

  // dst_host aggregates from wider window
  const dstHostEvents = recentRows.filter(r => r.destination_ip === row.destination_ip);
  const dstHostCount = Math.min(dstHostEvents.length, 255);
  const dstHostSrvCount = dstHostEvents.filter(r => (r.port || 0) === port).length;
  const dstHostSameSrvRate = dstHostCount > 0 ? dstHostSrvCount / dstHostCount : 0;

  // Unique hosts reaching same destination on different ports
  const uniqueSrcPorts = new Set(dstHostEvents.map(r => r.port || 0));
  const dstHostDiffSrvRate = dstHostCount > 0 ? (uniqueSrcPorts.size - 1) / Math.max(dstHostCount, 1) : 0;
  
  const sameSrcPortEvents = dstHostEvents.filter(r => (r.port || 0) === port);
  const dstHostSameSrcPortRate = dstHostCount > 0 ? sameSrcPortEvents.length / dstHostCount : 0;

  const dstHostSynOnly = dstHostEvents.filter(r => {
    const f = Array.isArray(r.flags) ? r.flags.map((s: string) => s.toUpperCase()) : [];
    return f.includes('SYN') && !f.includes('ACK');
  }).length;
  const dstHostSerrorRate = dstHostCount > 0 ? dstHostSynOnly / dstHostCount : 0;

  const dstHostRst = dstHostEvents.filter(r => {
    const f = Array.isArray(r.flags) ? r.flags.map((s: string) => s.toUpperCase()) : [];
    return f.includes('RST');
  }).length;
  const dstHostRerrorRate = dstHostCount > 0 ? dstHostRst / dstHostCount : 0;

  // Unique source hosts contacting the same dst on same service
  const uniqueSrcHosts = new Set(sameSrvEvents.map(r => r.source_ip));
  const srvDiffHostRate = srvCount > 0 ? (uniqueSrcHosts.size - 1) / Math.max(srvCount, 1) : 0;
  const dstHostSrvDiffHostRate = dstHostSrvCount > 0
    ? (new Set(dstHostEvents.filter(r => (r.port || 0) === port).map(r => r.source_ip)).size - 1) / Math.max(dstHostSrvCount, 1)
    : 0;

  return {
    duration: 0, // Not available from single packet; could be estimated from flow
    protocol_type: protocol,
    service,
    flag,
    src_bytes: packetSize,
    dst_bytes: Math.floor(packetSize * 0.7), // Estimated response bytes
    land: row.source_ip === row.destination_ip ? 1 : 0,
    wrong_fragment: 0,
    urgent: flags.some(f => f.toUpperCase() === 'URG') ? 1 : 0,
    hot: row.is_suspicious ? 1 : 0,
    num_failed_logins: 0,
    logged_in: 1,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    count,
    srv_count: srvCount,
    serror_rate: serrorRate,
    srv_serror_rate: serrorRate, // Same for service-level
    rerror_rate: rerrorRate,
    srv_rerror_rate: rerrorRate,
    same_srv_rate: sameSrvRate,
    diff_srv_rate: diffSrvRate,
    srv_diff_host_rate: srvDiffHostRate,
    dst_host_count: dstHostCount,
    dst_host_srv_count: dstHostSrvCount,
    dst_host_same_srv_rate: dstHostSameSrvRate,
    dst_host_diff_srv_rate: Math.min(dstHostDiffSrvRate, 1),
    dst_host_same_src_port_rate: dstHostSameSrcPortRate,
    dst_host_srv_diff_host_rate: Math.min(dstHostSrvDiffHostRate, 1),
    dst_host_serror_rate: dstHostSerrorRate,
    dst_host_srv_serror_rate: dstHostSerrorRate,
    dst_host_rerror_rate: dstHostRerrorRate,
    dst_host_srv_rerror_rate: dstHostRerrorRate,
  };
}

/**
 * Convert a NetworkEvent (from useIDSDataStore) into MLFeatures
 */
export function extractFeaturesFromEvent(
  event: NetworkEvent,
  recentEvents: NetworkEvent[]
): MLFeatures {
  // Convert NetworkEvent to traffic row format for reuse
  const toRow = (e: NetworkEvent): NetworkTrafficRow => ({
    id: e.id,
    source_ip: e.sourceIP,
    destination_ip: e.destinationIP,
    protocol: e.protocol,
    port: e.port,
    packet_size: e.packetSize,
    flags: e.flags,
    payload_preview: e.payload,
    created_at: e.timestamp,
  });

  return extractFeaturesFromTrafficRow(
    toRow(event),
    recentEvents.map(toRow)
  );
}

/**
 * Hook wrapper for convenience
 */
export const useNetworkFeatureExtractor = () => {
  const extract = useCallback((event: NetworkEvent, recentEvents: NetworkEvent[]): MLFeatures => {
    return extractFeaturesFromEvent(event, recentEvents);
  }, []);

  const extractFromTrafficRows = useCallback((
    row: NetworkTrafficRow,
    recentRows: NetworkTrafficRow[]
  ): MLFeatures => {
    return extractFeaturesFromTrafficRow(row, recentRows);
  }, []);

  return { extract, extractFromTrafficRows };
};
