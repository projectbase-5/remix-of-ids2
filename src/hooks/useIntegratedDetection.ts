import { useCallback, useEffect, useRef } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import type { LogEntry, FileEvent } from './useNetworkMonitor';
import type { MLModel, useMLPipeline } from './useMLPipeline';

export interface MLDetectionResult {
  id: string;
  timestamp: string;
  eventType: 'log' | 'file';
  eventId: string;
  prediction: string;
  confidence: number;
  isAnomaly: boolean;
  threatScore: number;
  features: number[];
  modelId: string;
  modelName: string;
}

export interface IntegratedDetectionConfig {
  enableMLDetection: boolean;
  confidenceThreshold: number;
  anomalyThreshold: number;
  autoCreateIncident: boolean;
  checkIPReputation: boolean;
  ipReputationThreshold: number;
}

const DEFAULT_CONFIG: IntegratedDetectionConfig = {
  enableMLDetection: true,
  confidenceThreshold: 0.7,
  anomalyThreshold: 0.8,
  autoCreateIncident: true,
  checkIPReputation: true,
  ipReputationThreshold: 50,
};

// Feature extraction from log entry for ML inference
const extractLogFeatures = (log: LogEntry): number[] => {
  const sourceMapping: Record<LogEntry['source'], number> = {
    'syslog': 1, 'firewall': 2, 'auth': 3, 'network': 4, 'application': 5, 'file_monitor': 6
  };
  const levelMapping: Record<LogEntry['level'], number> = {
    'debug': 1, 'info': 2, 'warning': 3, 'error': 4, 'critical': 5
  };
  const protocolMapping: Record<string, number> = {
    'TCP': 1, 'UDP': 2, 'ICMP': 3
  };

  // Parse IP octets for more granular features
  const parseIP = (ip: string | undefined): number[] => {
    if (!ip) return [0, 0, 0, 0];
    const parts = ip.split('.').map(Number);
    return parts.length === 4 ? parts : [0, 0, 0, 0];
  };

  const srcOctets = parseIP(log.sourceIP);
  const dstOctets = parseIP(log.destinationIP);

  return [
    sourceMapping[log.source] || 0,
    levelMapping[log.level] || 0,
    log.port || 0,
    protocolMapping[log.protocol || ''] || 0,
    srcOctets[0], srcOctets[1], srcOctets[2], srcOctets[3],
    dstOctets[0], dstOctets[1], dstOctets[2], dstOctets[3],
    log.threatIndicator ? 1 : 0,
    log.message.length,
    // Add time-based features
    new Date(log.timestamp).getHours(),
    new Date(log.timestamp).getMinutes(),
    // Port risk score
    [22, 23, 3389, 1433, 5432].includes(log.port || 0) ? 1 : 0,
    // Internal vs external IP indicator
    log.sourceIP?.startsWith('192.168.') || log.sourceIP?.startsWith('10.') ? 0 : 1,
  ];
};

// Feature extraction from file event
const extractFileFeatures = (event: FileEvent): number[] => {
  const eventTypeMapping: Record<FileEvent['eventType'], number> = {
    'created': 1, 'modified': 2, 'deleted': 3, 'accessed': 4, 'permission_changed': 5
  };

  const suspiciousExtensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.msi', '.scr'];
  const extension = event.fileName.slice(event.fileName.lastIndexOf('.')).toLowerCase();

  return [
    eventTypeMapping[event.eventType] || 0,
    event.fileSize || 0,
    event.isSuspicious ? 1 : 0,
    suspiciousExtensions.includes(extension) ? 1 : 0,
    event.filePath.toLowerCase().includes('temp') ? 1 : 0,
    event.filePath.toLowerCase().includes('downloads') ? 1 : 0,
    event.filePath.toLowerCase().includes('system32') ? 1 : 0,
    event.filePath.toLowerCase().includes('/etc') ? 1 : 0,
    new Date(event.timestamp).getHours(),
    // Process risk indicators
    ['powershell.exe', 'cmd.exe', 'bash', 'sh'].includes(event.process || '') ? 1 : 0,
  ];
};

// Simple anomaly detection using statistical methods
const detectAnomaly = (features: number[], historicalMeans: number[], historicalStds: number[]): number => {
  if (historicalMeans.length === 0 || features.length !== historicalMeans.length) {
    return 0;
  }

  let zScoreSum = 0;
  let validCount = 0;

  features.forEach((value, index) => {
    const std = historicalStds[index] || 1;
    if (std > 0) {
      const zScore = Math.abs((value - historicalMeans[index]) / std);
      zScoreSum += zScore;
      validCount++;
    }
  });

  const avgZScore = validCount > 0 ? zScoreSum / validCount : 0;
  // Convert to anomaly probability (sigmoid function)
  return 1 / (1 + Math.exp(-avgZScore + 2));
};

// Calculate threat score based on multiple factors
const calculateThreatScore = (
  prediction: string,
  confidence: number,
  anomalyScore: number,
  log?: LogEntry,
  fileEvent?: FileEvent
): number => {
  let score = 0;

  // Base score from ML prediction
  if (prediction !== 'normal' && prediction !== 'benign') {
    score += confidence * 40;
  }

  // Add anomaly contribution
  score += anomalyScore * 30;

  // Log-specific factors
  if (log) {
    if (log.level === 'critical') score += 15;
    else if (log.level === 'error') score += 10;
    else if (log.level === 'warning') score += 5;

    if (log.threatIndicator) score += 10;
    
    // High-risk ports
    if ([22, 23, 3389, 1433, 5432, 27017].includes(log.port || 0)) {
      score += 5;
    }
  }

  // File-specific factors
  if (fileEvent) {
    if (fileEvent.isSuspicious) score += 15;
    if (fileEvent.filePath.toLowerCase().includes('system32')) score += 10;
    if (fileEvent.filePath.toLowerCase().includes('/etc')) score += 10;
  }

  return Math.min(100, Math.round(score));
};

export function useIntegratedDetection(
  mlPipeline: ReturnType<typeof useMLPipeline>,
  config: IntegratedDetectionConfig = DEFAULT_CONFIG
) {
  const detectionResultsRef = useRef<MLDetectionResult[]>([]);
  const historicalFeaturesRef = useRef<number[][]>([]);
  const activeModelRef = useRef<MLModel | null>(null);
  const ipReputationCacheRef = useRef<Map<string, { score: number; timestamp: number }>>(new Map());

  // Update active model when models change
  useEffect(() => {
    const readyModel = mlPipeline.models.find(m => m.status === 'ready');
    if (readyModel) {
      activeModelRef.current = readyModel;
    }
  }, [mlPipeline.models]);

  // Calculate historical statistics for anomaly detection
  const updateHistoricalStats = useCallback((features: number[]) => {
    historicalFeaturesRef.current.push(features);
    if (historicalFeaturesRef.current.length > 1000) {
      historicalFeaturesRef.current = historicalFeaturesRef.current.slice(-500);
    }
  }, []);

  const getHistoricalStats = useCallback(() => {
    const features = historicalFeaturesRef.current;
    if (features.length < 10) return { means: [], stds: [] };

    const numFeatures = features[0].length;
    const means: number[] = [];
    const stds: number[] = [];

    for (let i = 0; i < numFeatures; i++) {
      const values = features.map(f => f[i]);
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
      means.push(mean);
      stds.push(Math.sqrt(variance));
    }

    return { means, stds };
  }, []);

  // Check IP reputation with caching
  const checkIPReputationCached = useCallback(async (ip: string): Promise<number> => {
    if (!config.checkIPReputation || !ip) return 100;

    const cached = ipReputationCacheRef.current.get(ip);
    if (cached && Date.now() - cached.timestamp < 5 * 60 * 1000) { // 5 min cache
      return cached.score;
    }

    try {
      // Check local database first
      const { data: localData } = await supabase
        .from('ip_reputation')
        .select('reputation_score')
        .eq('ip_address', ip)
        .single();

      if (localData) {
        ipReputationCacheRef.current.set(ip, { score: localData.reputation_score, timestamp: Date.now() });
        return localData.reputation_score;
      }

      // Call edge function for unknown IPs (in background)
      supabase.functions.invoke('check-ip-reputation', {
        body: { ip_address: ip }
      }).then(({ data }) => {
        if (data?.reputation_score !== undefined) {
          ipReputationCacheRef.current.set(ip, { score: data.reputation_score, timestamp: Date.now() });
        }
      }).catch(() => {
        // Ignore errors, use default score
      });

      return 100; // Default to neutral until checked
    } catch {
      return 100;
    }
  }, [config.checkIPReputation]);

  // Create incident automatically
  const createIncident = useCallback(async (
    result: MLDetectionResult,
    log?: LogEntry,
    fileEvent?: FileEvent,
    ipRepScore?: number
  ) => {
    if (!config.autoCreateIncident) return;

    try {
      const incidentData = {
        incident_type: result.prediction,
        severity: result.threatScore >= 80 ? 'critical' : 
                  result.threatScore >= 60 ? 'high' : 
                  result.threatScore >= 40 ? 'medium' : 'low',
        source_ip: log?.sourceIP || null,
        destination_ip: log?.destinationIP || null,
        source_port: log?.port || null,
        protocol: log?.protocol || null,
        details: {
          ml_prediction: result.prediction,
          ml_confidence: result.confidence,
          anomaly_score: result.isAnomaly ? 1 : 0,
          threat_score: result.threatScore,
          model_used: result.modelName,
          ip_reputation_score: ipRepScore,
          file_path: fileEvent?.filePath,
          event_type: result.eventType,
          features: result.features
        } as unknown as undefined,
        status: 'open'
      };

      const { error } = await supabase.from('incident_logs').insert([incidentData]);
      
      if (error) {
        console.error('Failed to create incident:', error);
      } else {
        toast.warning(`Incident created: ${result.prediction} (Score: ${result.threatScore})`);
      }
    } catch (error) {
      console.error('Error creating incident:', error);
    }
  }, [config.autoCreateIncident]);

  // Process log entry through ML detection
  const processLogEntry = useCallback(async (log: LogEntry): Promise<MLDetectionResult | null> => {
    if (!config.enableMLDetection) return null;

    try {
      const features = extractLogFeatures(log);
      updateHistoricalStats(features);

      const { means, stds } = getHistoricalStats();
      const anomalyScore = detectAnomaly(features, means, stds);

      let prediction = 'normal';
      let confidence = 0.5;

      // Use ML model if available
      const activeModel = activeModelRef.current;
      if (activeModel?.classifier) {
        try {
          const predictions = activeModel.classifier.predict([features]);
          prediction = predictions[0] === 0 ? 'normal' : 'attack';
          
          // Estimate confidence based on model metrics
          confidence = activeModel.metrics.accuracy || 0.7;
        } catch {
          // Fallback to rule-based detection
          prediction = log.threatIndicator ? 'suspicious' : 'normal';
          confidence = log.threatIndicator ? 0.8 : 0.6;
        }
      } else {
        // Rule-based fallback
        if (log.threatIndicator) {
          prediction = 'suspicious';
          confidence = 0.8;
        } else if (log.level === 'critical' || log.level === 'error') {
          prediction = 'potential_threat';
          confidence = 0.6;
        }
      }

      const isAnomaly = anomalyScore > config.anomalyThreshold;
      const threatScore = calculateThreatScore(prediction, confidence, anomalyScore, log);

      const result: MLDetectionResult = {
        id: `detection-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        eventType: 'log',
        eventId: log.id,
        prediction,
        confidence,
        isAnomaly,
        threatScore,
        features,
        modelId: activeModel?.id || 'rule-based',
        modelName: activeModel?.name || 'Rule-based Detection'
      };

      // Store detection result
      detectionResultsRef.current = [result, ...detectionResultsRef.current.slice(0, 499)];

      // Check IP reputation for suspicious IPs
      let ipRepScore: number | undefined;
      if (log.sourceIP && (prediction !== 'normal' || isAnomaly)) {
        ipRepScore = await checkIPReputationCached(log.sourceIP);
        
        // Boost threat score if IP has bad reputation
        if (ipRepScore < config.ipReputationThreshold) {
          result.threatScore = Math.min(100, result.threatScore + (config.ipReputationThreshold - ipRepScore) / 2);
        }
      }

      // Create incident if threat score exceeds threshold
      if (result.threatScore >= 50 || (confidence >= config.confidenceThreshold && prediction !== 'normal')) {
        await createIncident(result, log, undefined, ipRepScore);
        
        // Send alert notification for high-threat incidents
        if (result.threatScore >= 80) {
          supabase.functions.invoke('send-alert-notification', {
            body: {
              incident_type: result.prediction,
              severity: result.threatScore >= 80 ? 'critical' : 'high',
              threat_score: result.threatScore,
              source_ip: log.sourceIP,
              destination_ip: log.destinationIP,
              details: { ml_confidence: result.confidence, model: result.modelName }
            }
          }).catch(() => {});
        }
      }

      // Save prediction to database for model improvement
      if (result.threatScore >= 30) {
        supabase.from('predictions').insert([{
          prediction: result.prediction,
          confidence: result.confidence,
          is_anomaly: result.isAnomaly,
          features: result.features as unknown as undefined,
          model_id: activeModel?.id || null,
        }]).then(({ error }) => {
          if (error) console.error('Failed to save prediction:', error);
        });
      }

      return result;
    } catch (error) {
      console.error('Error processing log entry:', error);
      return null;
    }
  }, [config, updateHistoricalStats, getHistoricalStats, checkIPReputationCached, createIncident]);

  // Process file event through ML detection
  const processFileEvent = useCallback(async (event: FileEvent): Promise<MLDetectionResult | null> => {
    if (!config.enableMLDetection) return null;

    try {
      const features = extractFileFeatures(event);
      const { means, stds } = getHistoricalStats();
      const anomalyScore = detectAnomaly(features, means, stds);

      let prediction = 'normal';
      let confidence = 0.5;

      // Rule-based detection for files
      if (event.isSuspicious) {
        prediction = 'malware_indicator';
        confidence = 0.85;
      } else if (event.filePath.toLowerCase().includes('temp') && event.eventType === 'created') {
        prediction = 'suspicious_file';
        confidence = 0.6;
      }

      const isAnomaly = anomalyScore > config.anomalyThreshold;
      const threatScore = calculateThreatScore(prediction, confidence, anomalyScore, undefined, event);

      const result: MLDetectionResult = {
        id: `detection-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        eventType: 'file',
        eventId: event.id,
        prediction,
        confidence,
        isAnomaly,
        threatScore,
        features,
        modelId: 'file-rules',
        modelName: 'File Monitor Rules'
      };

      detectionResultsRef.current = [result, ...detectionResultsRef.current.slice(0, 499)];

      // Scan file hash if available and suspicious (validate hash format first)
      const isValidHash = (h: string) => /^[a-f0-9]{32}$/.test(h) || /^[a-f0-9]{40}$/.test(h) || /^[a-f0-9]{64}$/.test(h);
      if (event.fileHash && event.isSuspicious && isValidHash(event.fileHash.toLowerCase())) {
        supabase.functions.invoke('scan-file-hash', {
          body: { hash: event.fileHash }
        }).then(({ data }) => {
          if (data?.is_malicious) {
            result.prediction = 'malware_detected';
            result.threatScore = 95;
            createIncident(result, undefined, event);
          }
        }).catch(() => {
          // Ignore hash scan errors
        });
      }

      // Create incident for suspicious files
      if (result.threatScore >= 50) {
        await createIncident(result, undefined, event);
      }

      return result;
    } catch (error) {
      console.error('Error processing file event:', error);
      return null;
    }
  }, [config, getHistoricalStats, createIncident]);

  // Get recent detection results
  const getDetectionResults = useCallback((): MLDetectionResult[] => {
    return detectionResultsRef.current;
  }, []);

  // Get detection statistics
  const getDetectionStats = useCallback(() => {
    const results = detectionResultsRef.current;
    const totalDetections = results.length;
    const threats = results.filter(r => r.prediction !== 'normal' && r.prediction !== 'benign');
    const anomalies = results.filter(r => r.isAnomaly);
    const highThreat = results.filter(r => r.threatScore >= 70);

    return {
      totalDetections,
      threatsDetected: threats.length,
      anomaliesDetected: anomalies.length,
      highThreatCount: highThreat.length,
      averageThreatScore: threats.length > 0 
        ? threats.reduce((a, b) => a + b.threatScore, 0) / threats.length 
        : 0,
      modelActive: !!activeModelRef.current
    };
  }, []);

  // Clear detection history
  const clearDetectionHistory = useCallback(() => {
    detectionResultsRef.current = [];
    historicalFeaturesRef.current = [];
    ipReputationCacheRef.current.clear();
  }, []);

  return {
    processLogEntry,
    processFileEvent,
    getDetectionResults,
    getDetectionStats,
    clearDetectionHistory,
    config
  };
}
