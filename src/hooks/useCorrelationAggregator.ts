import { useState, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import type { CorrelationEvent } from './useThreatCorrelation';

export type EventSource = 'incident_log' | 'live_alert' | 'prediction';

export interface AggregatedEvent extends CorrelationEvent {
  eventSource: EventSource;
  originalId: string;
}

interface AggregatorOptions {
  windowMinutes?: number;
  includePredictions?: boolean;
  minPredictionConfidence?: number;
}

export function useCorrelationAggregator(options: AggregatorOptions = {}) {
  const {
    windowMinutes = 15,
    includePredictions = true,
    minPredictionConfidence = 0.7
  } = options;

  const [events, setEvents] = useState<AggregatedEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAllEvents = useCallback(async (customWindowMinutes?: number) => {
    setLoading(true);
    setError(null);
    
    const window = customWindowMinutes ?? windowMinutes;
    const since = new Date(Date.now() - window * 60 * 1000).toISOString();
    
    try {
      // Fetch from all three sources in parallel
      const [incidentResult, alertResult, predictionResult] = await Promise.all([
        supabase
          .from('incident_logs')
          .select('id, created_at, source_ip, destination_ip, incident_type, severity, details')
          .gte('created_at', since)
          .order('created_at', { ascending: false })
          .limit(500),
        
        supabase
          .from('live_alerts')
          .select('id, created_at, source_ip, destination_ip, alert_type, severity, metadata')
          .gte('created_at', since)
          .order('created_at', { ascending: false })
          .limit(500),
        
        includePredictions
          ? supabase
              .from('predictions')
              .select('id, created_at, prediction, confidence, features, is_anomaly')
              .gte('created_at', since)
              .gte('confidence', minPredictionConfidence)
              .eq('is_anomaly', true)
              .order('created_at', { ascending: false })
              .limit(200)
          : Promise.resolve({ data: [], error: null })
      ]);

      const aggregated: AggregatedEvent[] = [];

      // Process incident_logs
      if (incidentResult.data) {
        for (const incident of incidentResult.data) {
          const details = incident.details as Record<string, unknown> | null;
          aggregated.push({
            id: incident.id,
            originalId: incident.id,
            eventSource: 'incident_log',
            timestamp: incident.created_at,
            sourceIP: incident.source_ip || undefined,
            destinationIP: incident.destination_ip || undefined,
            attackType: incident.incident_type,
            severity: incident.severity,
            threatScore: (details?.threat_score as number) || severityToScore(incident.severity),
            details: details || undefined,
          });
        }
      }

      // Process live_alerts
      if (alertResult.data) {
        for (const alert of alertResult.data) {
          const metadata = alert.metadata as Record<string, unknown> | null;
          aggregated.push({
            id: alert.id,
            originalId: alert.id,
            eventSource: 'live_alert',
            timestamp: alert.created_at || new Date().toISOString(),
            sourceIP: alert.source_ip || undefined,
            destinationIP: alert.destination_ip || undefined,
            attackType: alert.alert_type,
            severity: alert.severity,
            threatScore: (metadata?.threat_score as number) || severityToScore(alert.severity),
            details: metadata || undefined,
          });
        }
      }

      // Process predictions (if enabled)
      if (predictionResult.data) {
        for (const pred of predictionResult.data) {
          const features = pred.features as Record<string, unknown>;
          aggregated.push({
            id: pred.id,
            originalId: pred.id,
            eventSource: 'prediction',
            timestamp: pred.created_at,
            sourceIP: (features?.source_ip as string) || undefined,
            destinationIP: (features?.destination_ip as string) || undefined,
            attackType: pred.prediction,
            severity: pred.confidence && pred.confidence > 0.9 ? 'critical' : 'high',
            threatScore: Math.round((pred.confidence || 0.7) * 100),
            details: features,
          });
        }
      }

      // Deduplicate: same IP + attack type within 1 minute
      const deduped = deduplicateEvents(aggregated);
      
      setEvents(deduped);
      return deduped;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to fetch events';
      setError(message);
      console.error('Correlation aggregation error:', err);
      return [];
    } finally {
      setLoading(false);
    }
  }, [windowMinutes, includePredictions, minPredictionConfidence]);

  return {
    events,
    loading,
    error,
    fetchAllEvents,
  };
}

function severityToScore(severity: string): number {
  switch (severity.toLowerCase()) {
    case 'critical': return 95;
    case 'high': return 80;
    case 'medium': return 55;
    case 'low': return 30;
    default: return 50;
  }
}

function deduplicateEvents(events: AggregatedEvent[]): AggregatedEvent[] {
  const seen = new Map<string, AggregatedEvent>();
  const ONE_MINUTE = 60 * 1000;

  // Sort by timestamp descending to keep most recent
  const sorted = [...events].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  for (const event of sorted) {
    const eventTime = new Date(event.timestamp).getTime();
    const key = `${event.sourceIP || 'unknown'}-${event.attackType.toLowerCase()}`;
    
    const existing = seen.get(key);
    if (existing) {
      const existingTime = new Date(existing.timestamp).getTime();
      if (Math.abs(eventTime - existingTime) < ONE_MINUTE) {
        // Keep the one with higher threat score
        if (event.threatScore > existing.threatScore) {
          seen.set(key, event);
        }
        continue;
      }
    }
    
    // Create a unique key with minute-bucket
    const bucket = Math.floor(eventTime / ONE_MINUTE);
    const uniqueKey = `${key}-${bucket}`;
    if (!seen.has(uniqueKey)) {
      seen.set(uniqueKey, event);
    }
  }

  return Array.from(seen.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
}
