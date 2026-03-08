import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Zap, Shield, AlertTriangle, CheckCircle, Brain, Activity } from 'lucide-react';
import { useMLPipeline, MLFeatures } from '@/hooks/useMLPipeline';
import { useIDSDataStore, NetworkEvent } from '@/hooks/useIDSDataStore';
import { extractFeaturesFromEvent } from '@/hooks/useNetworkFeatureExtractor';
import { supabase } from '@/integrations/supabase/client';

interface PredictionResult {
  id: string;
  timestamp: Date;
  prediction: string;
  confidence: number;
  features: MLFeatures;
  anomalyScore: number;
  processingTime: number;
}

interface RealtimeInferenceProps {
  activeModel?: any;
}

const RealtimeInference: React.FC<RealtimeInferenceProps> = ({ activeModel }) => {
  const [isInferenceActive, setIsInferenceActive] = useState(false);
  const [predictions, setPredictions] = useState<PredictionResult[]>([]);
  const [inferenceStats, setInferenceStats] = useState({
    totalPredictions: 0,
    threats: 0,
    avgConfidence: 0,
    avgProcessingTime: 0
  });
  const [adaptiveConfig, setAdaptiveConfig] = useState({
    environment: 'Cloud',
    resourceConstraints: { memory: 1024, cpu: 80, bandwidth: 1000 },
    updateFrequency: 300,
    batchSize: 10
  });

  const mlPipeline = useMLPipeline();
  const { networkEvents, addThreat } = useIDSDataStore();

  useEffect(() => {
    if (isInferenceActive && activeModel) {
      const interval = setInterval(() => {
        processNetworkEvents();
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [isInferenceActive, activeModel, networkEvents]);

  // Convert NetworkEvent to MLFeatures using real feature extraction
  const convertNetworkEventToFeatures = (event: NetworkEvent): MLFeatures => {
    return extractFeaturesFromEvent(event, networkEvents);
  };

  const processNetworkEvents = useCallback(async () => {
    if (!activeModel || networkEvents.length === 0) return;

    // Process the latest network events
    const recentEvents = networkEvents.slice(-adaptiveConfig.batchSize);
    
    for (const event of recentEvents) {
      try {
        const startTime = Date.now();
        const features = convertNetworkEventToFeatures(event);
        
        // Perform ML prediction using trained model
        const mlResult = await performMLPrediction(features);
        const processingTime = Date.now() - startTime;
        
        const result: PredictionResult = {
          id: crypto.randomUUID(),
          timestamp: new Date(),
          prediction: mlResult.prediction === 'attack' ? 'Attack' : 'BENIGN',
          confidence: mlResult.confidence,
          features,
          anomalyScore: mlResult.confidence,
          processingTime: mlResult.processingTime
        };

        setPredictions(prev => [result, ...prev.slice(0, 99)]); // Keep last 100 predictions

        // Update stats
        setInferenceStats(prev => {
          const total = prev.totalPredictions + 1;
          const threats = prev.threats + (mlResult.prediction !== 'normal' ? 1 : 0);
          const avgConf = (prev.avgConfidence * prev.totalPredictions + mlResult.confidence) / total;
          const avgTime = (prev.avgProcessingTime * prev.totalPredictions + mlResult.processingTime) / total;
          
          return {
            totalPredictions: total,
            threats,
            avgConfidence: avgConf,
            avgProcessingTime: avgTime
          };
        });

        // Create threat if attack detected
        if (mlResult.prediction !== 'normal' && mlResult.confidence > 0.7) {
          addThreat({
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            ruleId: `ML-${result.prediction}`,
            ruleName: `ML Detection: ${result.prediction}`,
            severity: mlResult.confidence > 0.9 ? 'high' : 'medium',
            confidence: mlResult.confidence,
            sourceIP: event.sourceIP,
            targetIP: event.destinationIP,
            attackType: result.prediction,
            description: `ML-detected ${result.prediction} with ${(mlResult.confidence * 100).toFixed(1)}% confidence`,
            evidence: [event],
            threatScore: mlResult.confidence
          });
        }

        // Store prediction in database
        await supabase.from('predictions').insert({
          features: features as any,
          prediction: result.prediction,
          confidence: mlResult.confidence,
          prediction_time_ms: mlResult.processingTime,
          is_anomaly: mlResult.prediction !== 'normal'
        });

      } catch (error) {
        console.error('Error processing network event:', error);
      }
    }
  }, [activeModel, networkEvents, adaptiveConfig, addThreat]);

  const performMLPrediction = async (features: MLFeatures): Promise<{ prediction: string; confidence: number; processingTime: number }> => {
    const startTime = performance.now();
    
    try {
      if (activeModel?.classifier) {
        // Use the trained model for real prediction
        const result = await mlPipeline.predict(activeModel, features);
        const endTime = performance.now();
        return {
          ...result,
          processingTime: endTime - startTime
        };
      } else {
        // Fallback to heuristic-based prediction
        let anomalyScore = 0;
        
        if (features.src_bytes > 1000) anomalyScore += 0.3;
        if (features.duration > 10000) anomalyScore += 0.25;
        if (features.dst_bytes > 15000) anomalyScore += 0.2;
        if (features.protocol_type === 'tcp' && features.service === 'http') anomalyScore += 0.15;
        if (features.hot > 0) anomalyScore += 0.4;
        
        const prediction = anomalyScore > 0.5 ? 'attack' : 'normal';
        const confidence = anomalyScore > 0.5 ? anomalyScore : 1 - anomalyScore;
        
        const endTime = performance.now();
        return { prediction, confidence, processingTime: endTime - startTime };
      }
    } catch (error) {
      console.error('Prediction error:', error);
      const endTime = performance.now();
      return {
        prediction: 'normal',
        confidence: 0.5,
        processingTime: endTime - startTime
      };
    }
  };

  const toggleInference = () => {
    setIsInferenceActive(!isInferenceActive);
  };

  const getEnvironmentConfig = () => {
    switch (adaptiveConfig.environment) {
      case 'IoT':
        return { 
          memory: 256, 
          cpu: 40, 
          bandwidth: 100,
          color: 'text-blue-600',
          icon: '📱'
        };
      case '5G':
        return { 
          memory: 512, 
          cpu: 60, 
          bandwidth: 500,
          color: 'text-purple-600',
          icon: '📡'
        };
      case 'Edge':
        return { 
          memory: 1024, 
          cpu: 80, 
          bandwidth: 1000,
          color: 'text-green-600',
          icon: '⚡'
        };
      default:
        return { 
          memory: 2048, 
          cpu: 100, 
          bandwidth: 10000,
          color: 'text-blue-600',
          icon: '☁️'
        };
    }
  };

  const envConfig = getEnvironmentConfig();

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center space-x-2">
            <Zap className="h-6 w-6 text-yellow-500" />
            <CardTitle>Real-time ML Inference</CardTitle>
          </div>
          <CardDescription>
            Live network intrusion detection using trained Decision Tree models
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-4">
              <Button 
                onClick={toggleInference}
                variant={isInferenceActive ? "destructive" : "default"}
                className="flex items-center space-x-2"
              >
                <Activity className={`h-4 w-4 ${isInferenceActive ? 'animate-pulse' : ''}`} />
                <span>{isInferenceActive ? 'Stop Inference' : 'Start Inference'}</span>
              </Button>
              
              {activeModel && (
                <Badge variant="outline" className="flex items-center space-x-1">
                  <Brain className="h-3 w-3" />
                  <span>{activeModel.algorithm || 'RandomForest'}</span>
                </Badge>
              )}
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">{inferenceStats.totalPredictions}</div>
                <div className="text-sm text-muted-foreground">Predictions</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{inferenceStats.threats}</div>
                <div className="text-sm text-muted-foreground">Threats</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">
                  {(inferenceStats.avgConfidence * 100).toFixed(1)}%
                </div>
                <div className="text-sm text-muted-foreground">Avg Confidence</div>
              </div>
            </div>
          </div>

          {/* Adaptive Environment Configuration */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="text-lg flex items-center space-x-2">
                <span>{envConfig.icon}</span>
                <span>Adaptive Environment: {adaptiveConfig.environment}</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <div className="text-sm text-muted-foreground">Memory Usage</div>
                  <Progress value={(envConfig.memory / 2048) * 100} className="h-2 mt-1" />
                  <div className="text-xs mt-1">{envConfig.memory}MB / 2048MB</div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground">CPU Usage</div>
                  <Progress value={envConfig.cpu} className="h-2 mt-1" />
                  <div className="text-xs mt-1">{envConfig.cpu}%</div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground">Bandwidth</div>
                  <Progress value={(envConfig.bandwidth / 10000) * 100} className="h-2 mt-1" />
                  <div className="text-xs mt-1">{envConfig.bandwidth}Mbps</div>
                </div>
              </div>
              
              <div className="flex items-center space-x-4 mt-4">
                {['IoT', '5G', 'Edge', 'Cloud'].map((env) => (
                  <Button
                    key={env}
                    variant={adaptiveConfig.environment === env ? "default" : "outline"}
                    size="sm"
                    onClick={() => setAdaptiveConfig(prev => ({ ...prev, environment: env }))}
                  >
                    {env}
                  </Button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Live Predictions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Live Predictions</CardTitle>
              <CardDescription>
                Real-time classification results from network traffic analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                <div className="space-y-3">
                  {predictions.map((pred) => (
                    <Alert key={pred.id} className={`${
                      pred.prediction === 'BENIGN' ? 'border-green-200' : 'border-red-200'
                    }`}>
                      <div className="flex items-center space-x-3">
                        {pred.prediction === 'BENIGN' ? (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        ) : (
                          <AlertTriangle className="h-4 w-4 text-red-500" />
                        )}
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <Badge variant={pred.prediction === 'BENIGN' ? 'default' : 'destructive'}>
                                {pred.prediction}
                              </Badge>
                              <span className="text-sm font-medium">
                                {(pred.confidence * 100).toFixed(1)}% confidence
                              </span>
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {pred.timestamp.toLocaleTimeString()} • {pred.processingTime}ms
                            </div>
                          </div>
                          <AlertDescription className="mt-1">
                            <div className="text-xs space-x-4">
                              <span>Protocol: {pred.features.protocol_type}</span>
                              <span>Service: {pred.features.service}</span>
                              <span>Bytes: {pred.features.src_bytes}</span>
                              <span>Anomaly Score: {pred.anomalyScore.toFixed(2)}</span>
                            </div>
                          </AlertDescription>
                        </div>
                      </div>
                    </Alert>
                  ))}
                  
                  {predictions.length === 0 && (
                    <div className="text-center text-muted-foreground py-8">
                      {isInferenceActive ? 'Waiting for network events to analyze...' : 'Start inference to see live predictions'}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </CardContent>
      </Card>
    </div>
  );
};

export default RealtimeInference;