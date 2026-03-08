import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertTriangle, TrendingUp, Wifi, Smartphone, Server, Cloud, Settings, RefreshCw } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useModelUpdatePipeline } from '@/hooks/useModelUpdatePipeline';

interface AdaptiveConfig {
  id?: string;
  environment_type: string;
  resource_constraints: {
    memory: number;
    cpu: number;
    bandwidth: number;
  };
  update_frequency: number;
  batch_size: number;
  learning_rate: number;
  drift_threshold: number;
  is_active: boolean;
}

interface DriftDetection {
  timestamp: Date;
  metric: string;
  current_value: number;
  baseline_value: number;
  drift_score: number;
  action_taken: string;
}

const AdaptiveLearning: React.FC = () => {
  const { driftStats, isRetraining, retrainProgress, retrainOnLiveData, checkDrift } = useModelUpdatePipeline();

  const [activeConfig, setActiveConfig] = useState<AdaptiveConfig>({
    environment_type: 'Cloud',
    resource_constraints: { memory: 2048, cpu: 80, bandwidth: 1000 },
    update_frequency: 3600,
    batch_size: 100,
    learning_rate: 0.001,
    drift_threshold: 0.05,
    is_active: true
  });
  
  const [savedConfigs, setSavedConfigs] = useState<AdaptiveConfig[]>([]);
  const [driftDetections, setDriftDetections] = useState<DriftDetection[]>([]);
  const [modelPerformance, setModelPerformance] = useState({
    currentAccuracy: 0,
    baseline: 0,
    adaptationCount: 0,
    lastUpdate: driftStats.lastRetrained || new Date()
  });

  useEffect(() => {
    fetchAdaptiveConfigs();
  }, []);

  // Update performance stats from real drift data
  useEffect(() => {
    if (driftStats.isDrifting) {
      const detection: DriftDetection = {
        timestamp: driftStats.lastChecked || new Date(),
        metric: 'prediction_distribution',
        current_value: 1 - driftStats.driftScore,
        baseline_value: 1,
        drift_score: driftStats.driftScore,
        action_taken: driftStats.driftScore > 0.1 ? 'Retraining Recommended' : 'Monitoring'
      };
      setDriftDetections(prev => [detection, ...prev.slice(0, 19)]);
    }
    setModelPerformance(prev => ({
      ...prev,
      lastUpdate: driftStats.lastRetrained || prev.lastUpdate,
    }));
  }, [driftStats.isDrifting, driftStats.driftScore, driftStats.lastChecked, driftStats.lastRetrained]);

  const fetchAdaptiveConfigs = async () => {
    try {
      const { data, error } = await supabase
        .from('adaptive_configs')
        .select('*')
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      setSavedConfigs((data || []).map(config => ({
        ...config,
        resource_constraints: config.resource_constraints as any
      })));
    } catch (error) {
      console.error('Error fetching adaptive configs:', error);
    }
  };

  const saveConfig = async () => {
    try {
      const { error } = await supabase
        .from('adaptive_configs')
        .insert(activeConfig);
      
      if (error) throw error;
      fetchAdaptiveConfigs();
    } catch (error) {
      console.error('Error saving config:', error);
    }
  };

  const handleRetrain = async () => {
    try {
      await retrainOnLiveData('RandomForest');
    } catch (e) {
      console.error('Retrain failed:', e);
    }
  };

  const getEnvironmentIcon = (type: string) => {
    switch (type) {
      case 'IoT': return <Smartphone className="h-4 w-4" />;
      case '5G': return <Wifi className="h-4 w-4" />;
      case 'Edge': return <Server className="h-4 w-4" />;
      default: return <Cloud className="h-4 w-4" />;
    }
  };

  const getEnvironmentConstraints = (type: string) => {
    switch (type) {
      case 'IoT':
        return { memory: 256, cpu: 30, bandwidth: 50, maxBatch: 10 };
      case '5G':
        return { memory: 512, cpu: 50, bandwidth: 200, maxBatch: 50 };
      case 'Edge':
        return { memory: 1024, cpu: 70, bandwidth: 500, maxBatch: 100 };
      default:
        return { memory: 2048, cpu: 100, bandwidth: 1000, maxBatch: 1000 };
    }
  };

  const handleEnvironmentChange = (environment: string) => {
    const constraints = getEnvironmentConstraints(environment);
    setActiveConfig(prev => ({
      ...prev,
      environment_type: environment,
      resource_constraints: {
        memory: constraints.memory,
        cpu: constraints.cpu,
        bandwidth: constraints.bandwidth
      },
      batch_size: Math.min(prev.batch_size, constraints.maxBatch)
    }));
  };

  const getDriftSeverity = (score: number) => {
    if (score > 0.1) return { label: 'High', color: 'text-red-600', variant: 'destructive' as const };
    if (score > 0.05) return { label: 'Medium', color: 'text-yellow-600', variant: 'secondary' as const };
    return { label: 'Low', color: 'text-green-600', variant: 'default' as const };
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center space-x-2">
            <TrendingUp className="h-6 w-6 text-blue-500" />
            <CardTitle>Adaptive Learning for IoT/5G Environments</CardTitle>
          </div>
          <CardDescription>
            Lightweight decision tree ensembles with real-time adaptation for resource-constrained environments
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="config" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="config">Configuration</TabsTrigger>
              <TabsTrigger value="drift">Drift Detection</TabsTrigger>
              <TabsTrigger value="performance">Performance</TabsTrigger>
            </TabsList>
            
            <TabsContent value="config" className="space-y-6">
              {/* Environment Selection */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Environment Type</CardTitle>
                  <CardDescription>
                    Select the deployment environment to optimize resource usage
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {['IoT', '5G', 'Edge', 'Cloud'].map((env) => (
                      <Button
                        key={env}
                        variant={activeConfig.environment_type === env ? "default" : "outline"}
                        className="flex flex-col items-center space-y-2 h-auto py-4"
                        onClick={() => handleEnvironmentChange(env)}
                      >
                        {getEnvironmentIcon(env)}
                        <span>{env}</span>
                      </Button>
                    ))}
                  </div>
                  
                  <div className="mt-6 grid grid-cols-3 gap-4">
                    <div>
                      <Label className="text-sm font-medium">Memory Limit</Label>
                      <div className="mt-1">
                        <Progress 
                          value={(activeConfig.resource_constraints.memory / 2048) * 100} 
                          className="h-2" 
                        />
                        <div className="text-xs text-muted-foreground mt-1">
                          {activeConfig.resource_constraints.memory}MB
                        </div>
                      </div>
                    </div>
                    <div>
                      <Label className="text-sm font-medium">CPU Usage</Label>
                      <div className="mt-1">
                        <Progress value={activeConfig.resource_constraints.cpu} className="h-2" />
                        <div className="text-xs text-muted-foreground mt-1">
                          {activeConfig.resource_constraints.cpu}%
                        </div>
                      </div>
                    </div>
                    <div>
                      <Label className="text-sm font-medium">Bandwidth</Label>
                      <div className="mt-1">
                        <Progress 
                          value={(activeConfig.resource_constraints.bandwidth / 1000) * 100} 
                          className="h-2" 
                        />
                        <div className="text-xs text-muted-foreground mt-1">
                          {activeConfig.resource_constraints.bandwidth}Mbps
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Learning Parameters */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Learning Parameters</CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="grid grid-cols-2 gap-6">
                    <div className="space-y-3">
                      <Label>Update Frequency (seconds)</Label>
                      <Slider
                        value={[activeConfig.update_frequency]}
                        onValueChange={(value) => setActiveConfig(prev => ({ ...prev, update_frequency: value[0] }))}
                        max={7200}
                        min={60}
                        step={60}
                      />
                      <div className="text-sm text-muted-foreground">
                        Current: {activeConfig.update_frequency}s ({Math.floor(activeConfig.update_frequency / 60)} minutes)
                      </div>
                    </div>
                    
                    <div className="space-y-3">
                      <Label>Batch Size</Label>
                      <Slider
                        value={[activeConfig.batch_size]}
                        onValueChange={(value) => setActiveConfig(prev => ({ ...prev, batch_size: value[0] }))}
                        max={getEnvironmentConstraints(activeConfig.environment_type).maxBatch}
                        min={10}
                        step={10}
                      />
                      <div className="text-sm text-muted-foreground">
                        Current: {activeConfig.batch_size} samples
                      </div>
                    </div>
                    
                    <div className="space-y-3">
                      <Label>Learning Rate</Label>
                      <Slider
                        value={[activeConfig.learning_rate * 1000]}
                        onValueChange={(value) => setActiveConfig(prev => ({ ...prev, learning_rate: value[0] / 1000 }))}
                        max={10}
                        min={0.1}
                        step={0.1}
                      />
                      <div className="text-sm text-muted-foreground">
                        Current: {activeConfig.learning_rate.toFixed(4)}
                      </div>
                    </div>
                    
                    <div className="space-y-3">
                      <Label>Drift Threshold</Label>
                      <Slider
                        value={[activeConfig.drift_threshold * 100]}
                        onValueChange={(value) => setActiveConfig(prev => ({ ...prev, drift_threshold: value[0] / 100 }))}
                        max={20}
                        min={1}
                        step={0.5}
                      />
                      <div className="text-sm text-muted-foreground">
                        Current: {(activeConfig.drift_threshold * 100).toFixed(1)}%
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Switch
                        id="adaptive-learning"
                        checked={activeConfig.is_active}
                        onCheckedChange={(checked) => setActiveConfig(prev => ({ ...prev, is_active: checked }))}
                      />
                      <Label htmlFor="adaptive-learning">Enable Adaptive Learning</Label>
                    </div>
                    <Button onClick={saveConfig} className="flex items-center space-x-2">
                      <Settings className="h-4 w-4" />
                      <span>Save Configuration</span>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
            
            <TabsContent value="drift" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Concept Drift Detection</CardTitle>
                  <CardDescription>
                    Real-time monitoring of model performance degradation
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {driftDetections.map((detection, index) => (
                      <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                        <div className="flex items-center space-x-3">
                          <AlertTriangle className={`h-5 w-5 ${getDriftSeverity(detection.drift_score).color}`} />
                          <div>
                            <div className="font-medium">{detection.metric} Drift Detected</div>
                            <div className="text-sm text-muted-foreground">
                              Current: {(detection.current_value * 100).toFixed(1)}% | 
                              Baseline: {(detection.baseline_value * 100).toFixed(1)}% | 
                              Drift: {(detection.drift_score * 100).toFixed(1)}%
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <Badge variant={getDriftSeverity(detection.drift_score).variant}>
                            {getDriftSeverity(detection.drift_score).label}
                          </Badge>
                          <div className="text-xs text-muted-foreground mt-1">
                            {detection.timestamp.toLocaleTimeString()}
                          </div>
                          <div className="text-xs font-medium text-blue-600">
                            {detection.action_taken}
                          </div>
                        </div>
                      </div>
                    ))}
                    
                    {driftDetections.length === 0 && (
                      <div className="text-center text-muted-foreground py-8">
                        No drift detected yet. System is monitoring performance metrics...
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
            
            <TabsContent value="performance" className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Current Performance</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">Model Accuracy</span>
                        <span className="text-2xl font-bold text-green-600">
                          {modelPerformance.currentAccuracy.toFixed(1)}%
                        </span>
                      </div>
                      <Progress value={modelPerformance.currentAccuracy} className="h-3" />
                      
                      <div className="flex items-center justify-between text-sm">
                        <span>Baseline: {modelPerformance.baseline}%</span>
                        <span className="text-green-600">
                          +{(modelPerformance.currentAccuracy - modelPerformance.baseline).toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Adaptation Statistics</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="text-center">
                        <div className="text-3xl font-bold text-blue-600">
                          {modelPerformance.adaptationCount}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          Total Adaptations
                        </div>
                      </div>
                      
                      <div className="text-center">
                        <div className="text-lg font-medium">
                          {modelPerformance.lastUpdate.toLocaleDateString()}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          Last Update: {modelPerformance.lastUpdate.toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
              
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Environment Optimizations</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div>
                      <h4 className="font-medium mb-2">Resource Efficiency</h4>
                      <div className="text-sm text-muted-foreground space-y-1">
                        <div>• Lightweight decision tree pruning for IoT devices</div>
                        <div>• Federated learning for 5G edge networks</div>
                        <div>• Dynamic batch sizing based on available bandwidth</div>
                        <div>• Memory-optimized model compression</div>
                      </div>
                    </div>
                    <div>
                      <h4 className="font-medium mb-2">Adaptation Strategies</h4>
                      <div className="text-sm text-muted-foreground space-y-1">
                        <div>• Ensemble pruning for computational efficiency</div>
                        <div>• Online gradient descent for rapid updates</div>
                        <div>• Drift-aware feature selection</div>
                        <div>• Real-time model selection based on performance</div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default AdaptiveLearning;