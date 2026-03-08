import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Brain, Play, Pause, BarChart3, Settings, TrendingUp, Shield, Download, XCircle, Database } from 'lucide-react';
import { useMLPipeline, MLModel } from '@/hooks/useMLPipeline';
import { useMLWorker } from '@/hooks/useMLWorker';
import { useModelUpdatePipeline } from '@/hooks/useModelUpdatePipeline';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { ModelEvaluationDashboard } from './ModelEvaluationDashboard';

interface MLModelManagerProps {
  onModelTrained?: (model: MLModel) => void;
}

const MLModelManager: React.FC<MLModelManagerProps> = ({ onModelTrained }) => {
  const mlPipeline = useMLPipeline();
  const { trainInWorker, cancelTraining, progress: workerProgress, isTraining: workerIsTraining } = useMLWorker();
  const { retrainOnLiveData, isRetraining, retrainProgress } = useModelUpdatePipeline();
  const { toast } = useToast();
  const [trainingProgress, setTrainingProgress] = useState(0);
  const [selectedModel, setSelectedModel] = useState<MLModel | null>(null);
  const [dbModels, setDbModels] = useState<any[]>([]);
  const [evaluations, setEvaluations] = useState<any[]>([]);
  const [selectedEvaluation, setSelectedEvaluation] = useState<any>(null);
  const [liveDataCount, setLiveDataCount] = useState(0);

  useEffect(() => {
    fetchModelsFromDatabase();
    fetchEvaluations();
    fetchLiveDataCount();
  }, []);

  const fetchModelsFromDatabase = async () => {
    try {
      const { data, error } = await supabase
        .from('ml_models')
        .select('*')
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      setDbModels(data || []);
    } catch (error) {
      console.error('Error fetching models:', error);
    }
  };

  const fetchEvaluations = async () => {
    try {
      const { data, error } = await supabase
        .from('model_evaluations')
        .select(`
          *,
          ml_models(name, algorithm)
        `)
        .order('created_at', { ascending: false });
      
      if (error) throw error;
      setEvaluations(data || []);
    } catch (error) {
      console.error('Error fetching evaluations:', error);
    }
  };

  const fetchLiveDataCount = async () => {
    try {
      const { count } = await supabase
        .from('training_data')
        .select('*', { count: 'exact', head: true });
      setLiveDataCount(count || 0);
    } catch (e) {
      console.error('Error fetching live data count:', e);
    }
  };

  // Sync worker progress to local state
  useEffect(() => {
    if (workerIsTraining || isRetraining) {
      setTrainingProgress(workerIsTraining ? workerProgress.value : retrainProgress.value);
    }
  }, [workerProgress, workerIsTraining, isRetraining, retrainProgress]);

  const trainNewModel = async (algorithm: 'RandomForest' | 'C4.5' | 'GBDT' | 'DT_SVM_Hybrid' = 'RandomForest') => {
    try {
      setTrainingProgress(5);
      
      // Run all heavy work in the Web Worker (synthetic data)
      const result = await trainInWorker(algorithm);
      
      // Save to database on main thread (needs Supabase client)
      await mlPipeline.saveMetricsToDatabase(algorithm, result.metrics);
      
      setTrainingProgress(100);
      
      toast({
        title: "Model Trained (Synthetic)",
        description: `${algorithm} model trained with ${(result.metrics.accuracy * 100).toFixed(2)}% accuracy`,
      });
      
      setTimeout(() => {
        fetchModelsFromDatabase();
        fetchEvaluations();
        setTrainingProgress(0);
      }, 1000);
      
    } catch (error: any) {
      if (error?.message === 'Training cancelled') {
        toast({
          title: "Training Cancelled",
          description: "Model training was cancelled",
        });
      } else {
        console.error('Error training model:', error);
        toast({
          title: "Training Failed",
          description: "An error occurred during model training",
          variant: "destructive",
        });
      }
      setTrainingProgress(0);
    }
  };

  const trainOnLiveData = async (algorithm: 'RandomForest' | 'C4.5' | 'GBDT' | 'DT_SVM_Hybrid' = 'RandomForest') => {
    try {
      setTrainingProgress(5);
      const result = await retrainOnLiveData(algorithm);
      setTrainingProgress(100);
      
      toast({
        title: "Model Trained on Live Data",
        description: `${algorithm} trained with ${(result.metrics.accuracy * 100).toFixed(2)}% accuracy using real data`,
      });
      
      setTimeout(() => {
        fetchModelsFromDatabase();
        fetchEvaluations();
        fetchLiveDataCount();
        setTrainingProgress(0);
      }, 1000);
    } catch (error: any) {
      if (error?.message === 'Training cancelled') {
        toast({ title: "Training Cancelled", description: "Model training was cancelled" });
      } else {
        console.error('Error training on live data:', error);
        toast({
          title: "Live Training Failed",
          description: error?.message || "An error occurred",
          variant: "destructive",
        });
      }
      setTrainingProgress(0);
    }
  };

  const loadModel = async (modelId: string) => {
    try {
      const model = await mlPipeline.loadModelFromDatabase(modelId);
      if (model) {
        setSelectedModel(model);
        onModelTrained?.(model);
        toast({
          title: "Model Loaded",
          description: `${model.name} is now active`,
        });
      }
    } catch (error) {
      console.error('Failed to load model:', error);
      toast({
        title: "Load Failed",
        description: "Could not load the model",
        variant: "destructive",
      });
    }
  };

  const formatMetric = (value: number) => (value * 100).toFixed(2) + '%';
  const formatTime = (ms: number) => ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center space-x-2">
            <Brain className="h-6 w-6 text-primary" />
            <CardTitle>ML Model Manager</CardTitle>
          </div>
          <CardDescription>
            Train and manage Decision Tree-based hybrid models for network intrusion detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-4 mb-6">
            <div className="flex space-x-2">
              <Button 
                onClick={() => trainNewModel('RandomForest')} 
                disabled={trainingProgress > 0}
                className="flex items-center space-x-2"
              >
                {trainingProgress > 0 ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                <span>Random Forest</span>
              </Button>
              <Button 
                onClick={() => trainNewModel('C4.5')} 
                disabled={trainingProgress > 0}
                variant="outline"
              >
                C4.5
              </Button>
              <Button 
                onClick={() => trainNewModel('GBDT')} 
                disabled={trainingProgress > 0}
                variant="outline"
              >
                GBDT
              </Button>
              <Button 
                onClick={() => trainNewModel('DT_SVM_Hybrid')} 
                disabled={trainingProgress > 0}
                variant="outline"
              >
                DT+SVM
              </Button>
            </div>
            
            {trainingProgress > 0 && (
              <div className="flex-1">
                <div className="flex items-center space-x-2">
                  <Progress value={trainingProgress} className="flex-1" />
                  <span className="text-sm text-muted-foreground whitespace-nowrap">
                    {workerProgress.stage || `${trainingProgress}%`}
                  </span>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={cancelTraining}
                    className="flex items-center space-x-1"
                  >
                    <XCircle className="h-3 w-3" />
                    <span>Cancel</span>
                  </Button>
                </div>
              </div>
            )}
          </div>

          <Tabs defaultValue="models" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="models">Models</TabsTrigger>
              <TabsTrigger value="evaluation">Evaluation</TabsTrigger>
              <TabsTrigger value="performance">Performance</TabsTrigger>
            </TabsList>
            
            <TabsContent value="models" className="space-y-4">
              <div className="grid gap-4">
                {dbModels.map((model) => (
                  <Card key={model.id} className="cursor-pointer hover:shadow-md transition-shadow"
                        onClick={() => setSelectedModel(model)}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="flex items-center space-x-2">
                            <Shield className="h-4 w-4 text-blue-500" />
                            <span className="font-medium">{model.name}</span>
                          </div>
                          <Badge variant={model.algorithm === 'RandomForest' ? 'default' : 'secondary'}>
                            {model.algorithm}
                          </Badge>
                          <Badge variant={model.status === 'ready' ? 'default' : 'secondary'}>
                            {model.status}
                          </Badge>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={(e) => {
                              e.stopPropagation();
                              loadModel(model.id);
                            }}
                          >
                            <Download className="h-4 w-4 mr-2" />
                            Load
                          </Button>
                          <div className="text-sm text-muted-foreground">
                            v{model.version}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>
            
            <TabsContent value="evaluation" className="space-y-4">
              <ScrollArea className="h-[400px]">
                {selectedEvaluation ? (
                  <div className="space-y-4">
                    <Button 
                      variant="outline" 
                      onClick={() => setSelectedEvaluation(null)}
                      className="mb-4"
                    >
                      ← Back to List
                    </Button>
                    <ModelEvaluationDashboard
                      metrics={{
                        accuracy: selectedEvaluation.accuracy || 0,
                        precision: selectedEvaluation.precision || 0,
                        recall: selectedEvaluation.recall || 0,
                        f1Score: selectedEvaluation.f1_score || 0,
                        detectionRate: selectedEvaluation.detection_rate || 0,
                        falsePositiveRate: selectedEvaluation.false_positive_rate || 0,
                      }}
                      confusionMatrix={selectedEvaluation.confusion_matrix || {
                        truePositive: 0,
                        trueNegative: 0,
                        falsePositive: 0,
                        falseNegative: 0
                      }}
                      modelName={selectedEvaluation.ml_models?.name || 'Unknown'}
                      algorithm={selectedEvaluation.ml_models?.algorithm || 'Unknown'}
                    />
                  </div>
                ) : (
                  <div className="space-y-4">
                    {evaluations.map((evaluation) => (
                      <Card 
                        key={evaluation.id}
                        className="cursor-pointer hover:bg-accent transition-colors"
                        onClick={() => setSelectedEvaluation(evaluation)}
                      >
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center space-x-2">
                              <BarChart3 className="h-4 w-4 text-green-500" />
                              <span className="font-medium">{evaluation.ml_models?.name}</span>
                              <Badge variant="outline">{evaluation.ml_models?.algorithm}</Badge>
                            </div>
                            <Badge variant="secondary">{evaluation.evaluation_type}</Badge>
                          </div>
                          
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <div className="text-center">
                              <div className="text-2xl font-bold text-green-600">
                                {formatMetric(evaluation.accuracy || 0)}
                              </div>
                              <div className="text-sm text-muted-foreground">Accuracy</div>
                            </div>
                            <div className="text-center">
                              <div className="text-2xl font-bold text-blue-600">
                                {formatMetric(evaluation.precision || 0)}
                              </div>
                              <div className="text-sm text-muted-foreground">Precision</div>
                            </div>
                            <div className="text-center">
                              <div className="text-2xl font-bold text-purple-600">
                                {formatMetric(evaluation.recall || 0)}
                              </div>
                              <div className="text-sm text-muted-foreground">Recall</div>
                            </div>
                            <div className="text-center">
                              <div className="text-2xl font-bold text-orange-600">
                                {formatMetric(evaluation.f1_score || 0)}
                              </div>
                              <div className="text-sm text-muted-foreground">F1-Score</div>
                            </div>
                          </div>
                          
                          <div className="mt-4 text-sm text-muted-foreground text-center">
                            Click to view detailed evaluation dashboard →
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </TabsContent>
            
            <TabsContent value="performance" className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <TrendingUp className="h-5 w-5" />
                      <span>Model Comparison</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {['RandomForest', 'C4.5', 'GBDT', 'DT_SVM_Hybrid'].map((algorithm) => {
                        const modelEvals = evaluations.filter(e => e.ml_models?.algorithm === algorithm);
                        const avgAccuracy = modelEvals.length > 0 
                          ? modelEvals.reduce((sum, e) => sum + (e.accuracy || 0), 0) / modelEvals.length
                          : 0;
                        
                        return (
                          <div key={algorithm} className="flex items-center space-x-3">
                            <div className="flex-1">
                              <div className="flex justify-between text-sm">
                                <span>{algorithm}</span>
                                <span>{formatMetric(avgAccuracy)}</span>
                              </div>
                              <Progress value={avgAccuracy * 100} className="h-2" />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Settings className="h-5 w-5" />
                      <span>Optimization Focus</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="text-sm">
                        <div className="font-medium mb-2">Low False Positive Rate (FPR)</div>
                        <div className="text-muted-foreground">
                          Optimized for minimal false alarms while maintaining high detection accuracy
                        </div>
                      </div>
                      <div className="text-sm">
                        <div className="font-medium mb-2">Enhanced U2R & R2L Detection</div>
                        <div className="text-muted-foreground">
                          Specialized detection for User-to-Root and Remote-to-Local attacks
                        </div>
                      </div>
                      <div className="text-sm">
                        <div className="font-medium mb-2">IoT/5G Adaptive Learning</div>
                        <div className="text-muted-foreground">
                          Lightweight models for resource-constrained environments
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default MLModelManager;