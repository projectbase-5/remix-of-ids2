/**
 * useModelUpdatePipeline — Drift detection, retraining triggers, and feedback loop
 * =================================================================================
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useMLWorker } from './useMLWorker';
import { useMLPipeline } from './useMLPipeline';
import { extractFeaturesFromTrafficRow, NetworkTrafficRow } from './useNetworkFeatureExtractor';

export interface DriftStats {
  driftScore: number;
  isDrifting: boolean;
  baselineDistribution: Record<string, number>;
  currentDistribution: Record<string, number>;
  lastChecked: Date | null;
  lastRetrained: Date | null;
  pendingFeedbackCount: number;
  windowSize: number;
}

export const useModelUpdatePipeline = () => {
  const { trainInWorker, isTraining, progress } = useMLWorker();
  const mlPipeline = useMLPipeline();

  const [driftStats, setDriftStats] = useState<DriftStats>({
    driftScore: 0,
    isDrifting: false,
    baselineDistribution: {},
    currentDistribution: {},
    lastChecked: null,
    lastRetrained: null,
    pendingFeedbackCount: 0,
    windowSize: 100,
  });

  const predictionWindowRef = useRef<string[]>([]);
  const baselineRef = useRef<Record<string, number>>({});

  // Monitor prediction distribution for drift
  const addPrediction = useCallback((label: string) => {
    predictionWindowRef.current.push(label);
    // Keep sliding window
    if (predictionWindowRef.current.length > driftStats.windowSize) {
      predictionWindowRef.current = predictionWindowRef.current.slice(-driftStats.windowSize);
    }
  }, [driftStats.windowSize]);

  // Check for drift
  const checkDrift = useCallback((threshold: number = 0.1) => {
    const window = predictionWindowRef.current;
    if (window.length < 20) return; // Need minimum samples

    // Compute current distribution
    const currentDist: Record<string, number> = {};
    window.forEach(label => {
      currentDist[label] = (currentDist[label] || 0) + 1;
    });
    // Normalize
    Object.keys(currentDist).forEach(k => {
      currentDist[k] = currentDist[k] / window.length;
    });

    // If no baseline, set it
    if (Object.keys(baselineRef.current).length === 0) {
      baselineRef.current = { ...currentDist };
      setDriftStats(prev => ({
        ...prev,
        baselineDistribution: { ...currentDist },
        currentDistribution: { ...currentDist },
        driftScore: 0,
        isDrifting: false,
        lastChecked: new Date(),
      }));
      return;
    }

    // Calculate KL-divergence-like drift score
    const allKeys = new Set([...Object.keys(baselineRef.current), ...Object.keys(currentDist)]);
    let driftScore = 0;
    allKeys.forEach(key => {
      const baseline = baselineRef.current[key] || 0.001;
      const current = currentDist[key] || 0.001;
      driftScore += Math.abs(current - baseline);
    });
    driftScore = driftScore / allKeys.size; // Normalize by number of classes

    const isDrifting = driftScore > threshold;

    setDriftStats(prev => ({
      ...prev,
      driftScore,
      isDrifting,
      currentDistribution: { ...currentDist },
      lastChecked: new Date(),
    }));
  }, []);

  // Fetch pending feedback count
  const fetchPendingFeedback = useCallback(async () => {
    try {
      const { count, error } = await supabase
        .from('predictions')
        .select('*', { count: 'exact', head: true })
        .eq('feedback_provided', false)
        .not('actual_label', 'is', null);

      if (!error && count !== null) {
        setDriftStats(prev => ({ ...prev, pendingFeedbackCount: count }));
      }
    } catch (e) {
      console.error('Error fetching feedback count:', e);
    }
  }, []);

  // Submit analyst feedback on a prediction
  const submitFeedback = useCallback(async (predictionId: string, actualLabel: string) => {
    try {
      // Update prediction with actual label
      await supabase
        .from('predictions')
        .update({ actual_label: actualLabel, feedback_provided: true })
        .eq('id', predictionId);

      // Also write to training_data for future model training
      const { data: prediction } = await supabase
        .from('predictions')
        .select('features')
        .eq('id', predictionId)
        .single();

      if (prediction) {
        await supabase.from('training_data').insert({
          record_id: `feedback-${predictionId}`,
          features: prediction.features,
          label: actualLabel,
          attack_category: actualLabel === 'BENIGN' ? null : actualLabel,
          severity: actualLabel === 'BENIGN' ? 0 : 3,
        });
      }

      fetchPendingFeedback();
    } catch (e) {
      console.error('Error submitting feedback:', e);
    }
  }, [fetchPendingFeedback]);

  // Retrain on live data
  const retrainOnLiveData = useCallback(async (algorithm: string = 'RandomForest') => {
    try {
      // Fetch recent network traffic
      const { data: trafficRows, error: trafficError } = await supabase
        .from('network_traffic')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(1000);

      if (trafficError) throw trafficError;

      // Fetch labeled training data
      const { data: labeledData, error: labeledError } = await supabase
        .from('training_data')
        .select('features, label')
        .limit(1000);

      if (labeledError) throw labeledError;

      // Build training set from labeled data
      const features: number[][] = [];
      const labels: string[] = [];

      if (labeledData && labeledData.length > 0) {
        labeledData.forEach(row => {
          const f = row.features as any;
          if (f && typeof f === 'object') {
            // Extract feature vector from stored features
            const featureObj = extractFeaturesFromTrafficRow({
              id: '',
              source_ip: f.source_ip || '0.0.0.0',
              destination_ip: f.destination_ip || '0.0.0.0',
              protocol: f.protocol || 'tcp',
              port: f.port || 0,
              packet_size: f.packet_size || 0,
              flags: f.flags || [],
              created_at: new Date().toISOString(),
            }, []);
            
            // Convert MLFeatures to number array (same order as worker)
            const protocolMap: Record<string, number> = { tcp: 1, udp: 2, icmp: 3 };
            const serviceMap: Record<string, number> = { http: 1, ftp: 2, smtp: 3, ssh: 4, telnet: 5, other: 6 };
            const flagMap: Record<string, number> = { SF: 1, S0: 2, REJ: 3, RSTR: 4, SH: 5, other: 6 };
            
            features.push([
              featureObj.duration,
              protocolMap[featureObj.protocol_type] || 0,
              serviceMap[featureObj.service] || 6,
              flagMap[featureObj.flag] || 6,
              featureObj.src_bytes, featureObj.dst_bytes, featureObj.land,
              featureObj.wrong_fragment, featureObj.urgent, featureObj.hot,
              featureObj.num_failed_logins, featureObj.logged_in,
              featureObj.num_compromised, featureObj.root_shell, featureObj.su_attempted,
              featureObj.num_root, featureObj.num_file_creations, featureObj.num_shells,
              featureObj.num_access_files, featureObj.num_outbound_cmds,
              featureObj.is_host_login, featureObj.is_guest_login,
              featureObj.count, featureObj.srv_count,
              featureObj.serror_rate, featureObj.srv_serror_rate,
              featureObj.rerror_rate, featureObj.srv_rerror_rate,
              featureObj.same_srv_rate, featureObj.diff_srv_rate,
              featureObj.srv_diff_host_rate, featureObj.dst_host_count,
              featureObj.dst_host_srv_count, featureObj.dst_host_same_srv_rate,
              featureObj.dst_host_diff_srv_rate, featureObj.dst_host_same_src_port_rate,
              featureObj.dst_host_srv_diff_host_rate, featureObj.dst_host_serror_rate,
              featureObj.dst_host_srv_serror_rate, featureObj.dst_host_rerror_rate,
              featureObj.dst_host_srv_rerror_rate,
            ]);
            labels.push(row.label);
          }
        });
      }

      // If we have enough labeled data, train on it
      if (features.length >= 50) {
        const result = await trainInWorker(algorithm, { features, labels });
        await mlPipeline.saveMetricsToDatabase(algorithm, result.metrics);

        // Update baseline after retraining
        baselineRef.current = { ...driftStats.currentDistribution };
        setDriftStats(prev => ({
          ...prev,
          lastRetrained: new Date(),
          isDrifting: false,
          driftScore: 0,
          baselineDistribution: { ...prev.currentDistribution },
        }));

        return result;
      } else {
        // Fall back to synthetic + any real data we have
        const result = await trainInWorker(algorithm, features.length > 0 ? { features, labels } : undefined);
        await mlPipeline.saveMetricsToDatabase(algorithm, result.metrics);

        setDriftStats(prev => ({
          ...prev,
          lastRetrained: new Date(),
        }));

        return result;
      }
    } catch (error) {
      console.error('Retrain failed:', error);
      throw error;
    }
  }, [trainInWorker, mlPipeline, driftStats.currentDistribution]);

  // Periodic drift check
  useEffect(() => {
    const interval = setInterval(() => {
      checkDrift();
      fetchPendingFeedback();
    }, 30000); // Every 30s

    return () => clearInterval(interval);
  }, [checkDrift, fetchPendingFeedback]);

  return {
    driftStats,
    isRetraining: isTraining,
    retrainProgress: progress,
    addPrediction,
    checkDrift,
    submitFeedback,
    retrainOnLiveData,
    fetchPendingFeedback,
  };
};
