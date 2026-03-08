import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';
import { AlertCircle, TrendingUp, Target, Activity } from "lucide-react";

interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  detectionRate: number;
  falsePositiveRate: number;
}

interface ConfusionMatrix {
  truePositive: number;
  trueNegative: number;
  falsePositive: number;
  falseNegative: number;
}

interface ModelEvaluationDashboardProps {
  metrics: ModelMetrics;
  confusionMatrix: ConfusionMatrix;
  modelName: string;
  algorithm: string;
}

export const ModelEvaluationDashboard = ({ 
  metrics, 
  confusionMatrix, 
  modelName, 
  algorithm 
}: ModelEvaluationDashboardProps) => {
  
  const metricsData = [
    { name: 'Accuracy', value: metrics.accuracy * 100 },
    { name: 'Precision', value: metrics.precision * 100 },
    { name: 'Recall', value: metrics.recall * 100 },
    { name: 'F1 Score', value: metrics.f1Score * 100 },
  ];

  const confusionData = [
    { category: 'True Positive', value: confusionMatrix.truePositive, fill: 'hsl(var(--chart-1))' },
    { category: 'True Negative', value: confusionMatrix.trueNegative, fill: 'hsl(var(--chart-2))' },
    { category: 'False Positive', value: confusionMatrix.falsePositive, fill: 'hsl(var(--chart-3))' },
    { category: 'False Negative', value: confusionMatrix.falseNegative, fill: 'hsl(var(--chart-4))' },
  ];

  const getMetricColor = (value: number) => {
    if (value >= 0.9) return 'text-green-500';
    if (value >= 0.7) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getMetricBadge = (value: number) => {
    if (value >= 0.9) return 'default';
    if (value >= 0.7) return 'secondary';
    return 'destructive';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">{modelName}</h2>
          <p className="text-muted-foreground">Algorithm: {algorithm}</p>
        </div>
        <Badge variant={getMetricBadge(metrics.accuracy)} className="text-lg px-4 py-2">
          {(metrics.accuracy * 100).toFixed(2)}% Accuracy
        </Badge>
      </div>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Detection Rate</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getMetricColor(metrics.detectionRate)}`}>
              {(metrics.detectionRate * 100).toFixed(2)}%
            </div>
            <Progress value={metrics.detectionRate * 100} className="mt-2" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">False Positive Rate</CardTitle>
            <AlertCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${metrics.falsePositiveRate < 0.1 ? 'text-green-500' : 'text-red-500'}`}>
              {(metrics.falsePositiveRate * 100).toFixed(2)}%
            </div>
            <Progress value={metrics.falsePositiveRate * 100} className="mt-2" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Precision</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getMetricColor(metrics.precision)}`}>
              {(metrics.precision * 100).toFixed(2)}%
            </div>
            <Progress value={metrics.precision * 100} className="mt-2" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Recall</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getMetricColor(metrics.recall)}`}>
              {(metrics.recall * 100).toFixed(2)}%
            </div>
            <Progress value={metrics.recall * 100} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Performance Metrics Bar Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Performance Metrics</CardTitle>
            <CardDescription>Overall model performance indicators</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={metricsData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Legend />
                <Bar dataKey="value" fill="hsl(var(--primary))" name="Score (%)" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Confusion Matrix */}
        <Card>
          <CardHeader>
            <CardTitle>Confusion Matrix</CardTitle>
            <CardDescription>Prediction distribution breakdown</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={confusionData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="category" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="value" fill="hsl(var(--primary))" name="Count" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Confusion Matrix Grid */}
      <Card>
        <CardHeader>
          <CardTitle>Confusion Matrix Details</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4">
            <div className="border rounded-lg p-4 bg-green-50 dark:bg-green-950">
              <div className="text-sm text-muted-foreground">True Positive</div>
              <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                {confusionMatrix.truePositive}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Correctly identified attacks</div>
            </div>
            <div className="border rounded-lg p-4 bg-blue-50 dark:bg-blue-950">
              <div className="text-sm text-muted-foreground">True Negative</div>
              <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">
                {confusionMatrix.trueNegative}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Correctly identified normal traffic</div>
            </div>
            <div className="border rounded-lg p-4 bg-red-50 dark:bg-red-950">
              <div className="text-sm text-muted-foreground">False Positive</div>
              <div className="text-3xl font-bold text-red-600 dark:text-red-400">
                {confusionMatrix.falsePositive}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Normal traffic flagged as attack</div>
            </div>
            <div className="border rounded-lg p-4 bg-orange-50 dark:bg-orange-950">
              <div className="text-sm text-muted-foreground">False Negative</div>
              <div className="text-3xl font-bold text-orange-600 dark:text-orange-400">
                {confusionMatrix.falseNegative}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Missed attacks</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
