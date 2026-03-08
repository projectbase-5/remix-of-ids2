import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Upload, FileSpreadsheet, Database, Trash2, Eye, 
  CheckCircle, AlertCircle, BarChart3, Brain, Loader2,
  FileUp, Table, PieChart
} from 'lucide-react';
import { useDatasetManager, Dataset } from '@/hooks/useDatasetManager';
import { toast } from 'sonner';

interface DatasetManagerProps {
  onDatasetReady?: (datasetId: string, features: number[][], labels: string[]) => void;
}

const DatasetManager: React.FC<DatasetManagerProps> = ({ onDatasetReady }) => {
  const {
    datasets,
    currentDataset,
    isLoading,
    uploadProgress,
    loadDatasets,
    uploadCSV,
    deleteDataset,
    selectDataset,
    getDatasetStats,
    getTrainingDataForML,
    setUploadProgress
  } = useDatasetManager();

  const [isDragging, setIsDragging] = useState(false);
  const [previewData, setPreviewData] = useState<any[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadDatasets();
  }, [loadDatasets]);

  // Handle file drop
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileUpload(files[0]);
    }
  }, []);

  // Handle file selection
  const handleFileUpload = async (file: File) => {
    if (!file.name.endsWith('.csv')) {
      toast.error('Please upload a CSV file');
      return;
    }

    const maxSize = 100 * 1024 * 1024; // 100MB
    if (file.size > maxSize) {
      toast.error('File size exceeds 100MB limit');
      return;
    }

    await uploadCSV(file);
  };

  // Prepare dataset for training
  const handlePrepareForTraining = async (datasetId: string) => {
    const data = await getTrainingDataForML(datasetId);
    if (data && onDatasetReady) {
      onDatasetReady(datasetId, data.features, data.labels);
      toast.success('Dataset prepared for training!');
    }
  };

  // Load preview data when dataset is selected
  useEffect(() => {
    if (currentDataset?.records) {
      setPreviewData(currentDataset.records.slice(0, 20));
    }
  }, [currentDataset]);

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  return (
    <div className="space-y-6">
      {/* Upload Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Dataset Upload
          </CardTitle>
          <CardDescription>
            Upload CICIDS2017, UNSW-NB15, KDD99/NSL-KDD, or custom CSV datasets
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Drop Zone */}
          <div
            className={`
              border-2 border-dashed rounded-lg p-8 text-center transition-colors
              ${isDragging ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'}
              ${uploadProgress?.stage === 'parsing' || uploadProgress?.stage === 'saving' ? 'opacity-50 pointer-events-none' : ''}
            `}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv"
              className="hidden"
              onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
            />
            
            <FileUp className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <h3 className="text-lg font-medium mb-2">Drop your dataset here</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Supports CSV files up to 100MB
            </p>
            <Button 
              onClick={() => fileInputRef.current?.click()}
              disabled={uploadProgress?.stage === 'parsing' || uploadProgress?.stage === 'saving'}
            >
              <FileSpreadsheet className="h-4 w-4 mr-2" />
              Select CSV File
            </Button>

            {/* Supported Formats */}
            <div className="flex justify-center gap-2 mt-4 flex-wrap">
              <Badge variant="secondary">CICIDS2017</Badge>
              <Badge variant="secondary">UNSW-NB15</Badge>
              <Badge variant="secondary">KDD99/NSL-KDD</Badge>
              <Badge variant="secondary">Custom CSV</Badge>
            </div>
          </div>

          {/* Upload Progress */}
          {uploadProgress && uploadProgress.stage !== 'complete' && (
            <div className="mt-4 space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2">
                  {uploadProgress.stage === 'error' ? (
                    <AlertCircle className="h-4 w-4 text-destructive" />
                  ) : (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  )}
                  {uploadProgress.message}
                </span>
                <span>{uploadProgress.progress}%</span>
              </div>
              <Progress 
                value={uploadProgress.progress} 
                className={uploadProgress.stage === 'error' ? 'bg-destructive/20' : ''} 
              />
            </div>
          )}

          {uploadProgress?.stage === 'complete' && (
            <div className="mt-4 flex items-center gap-2 text-sm text-green-600">
              <CheckCircle className="h-4 w-4" />
              {uploadProgress.message}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Datasets List & Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Datasets List */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              Available Datasets
            </CardTitle>
            <CardDescription>
              {datasets.length} dataset{datasets.length !== 1 ? 's' : ''} loaded
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[400px]">
              {isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin" />
                </div>
              ) : datasets.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No datasets uploaded yet</p>
                  <p className="text-sm mt-2">Upload a CSV file to get started</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {datasets.map((dataset) => (
                    <div
                      key={dataset.id}
                      className={`
                        p-3 rounded-lg border cursor-pointer transition-colors
                        ${currentDataset?.id === dataset.id 
                          ? 'border-primary bg-primary/5' 
                          : 'hover:border-primary/50'
                        }
                      `}
                      onClick={() => selectDataset(dataset.id)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium truncate">{dataset.name}</h4>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge variant="outline" className="text-xs">
                              {dataset.format}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {formatNumber(dataset.totalRecords)} records
                            </span>
                          </div>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-muted-foreground hover:text-destructive"
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteDataset(dataset.id);
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Dataset Details & Preview */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Eye className="h-5 w-5" />
              Dataset Details
            </CardTitle>
            <CardDescription>
              {currentDataset ? currentDataset.name : 'Select a dataset to view details'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {currentDataset ? (
              <Tabs defaultValue="stats">
                <TabsList className="mb-4">
                  <TabsTrigger value="stats">
                    <PieChart className="h-4 w-4 mr-2" />
                    Statistics
                  </TabsTrigger>
                  <TabsTrigger value="preview">
                    <Table className="h-4 w-4 mr-2" />
                    Preview
                  </TabsTrigger>
                  <TabsTrigger value="train">
                    <Brain className="h-4 w-4 mr-2" />
                    Training
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="stats">
                  <DatasetStats dataset={currentDataset} getDatasetStats={getDatasetStats} />
                </TabsContent>

                <TabsContent value="preview">
                  <DatasetPreview data={previewData} />
                </TabsContent>

                <TabsContent value="train">
                  <TrainingSection 
                    dataset={currentDataset} 
                    onPrepare={() => handlePrepareForTraining(currentDataset.id)} 
                  />
                </TabsContent>
              </Tabs>
            ) : (
              <div className="text-center py-12 text-muted-foreground">
                <BarChart3 className="h-16 w-16 mx-auto mb-4 opacity-50" />
                <p className="text-lg">No dataset selected</p>
                <p className="text-sm mt-2">
                  Select a dataset from the list or upload a new one
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

// Dataset Statistics Component
const DatasetStats: React.FC<{ 
  dataset: Dataset; 
  getDatasetStats: (dataset: Dataset) => any;
}> = ({ dataset, getDatasetStats }) => {
  const stats = getDatasetStats(dataset);
  
  return (
    <div className="space-y-6">
      {/* Key Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 bg-muted/50 rounded-lg text-center">
          <div className="text-2xl font-bold">{stats.totalRecords.toLocaleString()}</div>
          <div className="text-sm text-muted-foreground">Total Records</div>
        </div>
        <div className="p-4 bg-muted/50 rounded-lg text-center">
          <div className="text-2xl font-bold">{stats.featuresCount}</div>
          <div className="text-sm text-muted-foreground">Features</div>
        </div>
        <div className="p-4 bg-muted/50 rounded-lg text-center">
          <div className="text-2xl font-bold text-green-600">{stats.normalPercentage}%</div>
          <div className="text-sm text-muted-foreground">Normal Traffic</div>
        </div>
        <div className="p-4 bg-muted/50 rounded-lg text-center">
          <div className="text-2xl font-bold text-red-600">{stats.attackPercentage}%</div>
          <div className="text-sm text-muted-foreground">Attack Traffic</div>
        </div>
      </div>

      {/* Class Distribution */}
      <div>
        <h4 className="font-medium mb-3">Class Distribution</h4>
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div className="w-20 text-sm">Normal</div>
            <div className="flex-1 bg-muted rounded-full h-4 overflow-hidden">
              <div 
                className="h-full bg-green-500 transition-all"
                style={{ width: `${stats.normalPercentage}%` }}
              />
            </div>
            <div className="w-24 text-sm text-right">{stats.normalCount.toLocaleString()}</div>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-20 text-sm">Attack</div>
            <div className="flex-1 bg-muted rounded-full h-4 overflow-hidden">
              <div 
                className="h-full bg-red-500 transition-all"
                style={{ width: `${stats.attackPercentage}%` }}
              />
            </div>
            <div className="w-24 text-sm text-right">{stats.attackCount.toLocaleString()}</div>
          </div>
        </div>
      </div>

      {/* Attack Categories */}
      {stats.attackCategories.length > 0 && (
        <div>
          <h4 className="font-medium mb-3">Attack Categories</h4>
          <div className="flex flex-wrap gap-2">
            {stats.attackCategories.map((cat: string) => (
              <Badge key={cat} variant="secondary">
                {cat}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {/* Dataset Info */}
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">Format:</span>
          <span className="ml-2 font-medium">{dataset.format}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Version:</span>
          <span className="ml-2 font-medium">{dataset.version}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Source:</span>
          <span className="ml-2 font-medium">{dataset.source}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Balance:</span>
          <Badge variant={stats.isBalanced ? "default" : "outline"} className="ml-2">
            {stats.isBalanced ? 'Balanced' : 'Imbalanced'}
          </Badge>
        </div>
      </div>
    </div>
  );
};

// Dataset Preview Component
const DatasetPreview: React.FC<{ data: any[] }> = ({ data }) => {
  if (data.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Table className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No preview data available</p>
      </div>
    );
  }

  const featureKeys = Object.keys(data[0].features || {}).slice(0, 8);

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Showing first {data.length} records (first 8 features)
      </p>
      <ScrollArea className="h-[300px]">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-background">
            <tr className="border-b">
              <th className="text-left p-2">#</th>
              <th className="text-left p-2">Label</th>
              <th className="text-left p-2">Category</th>
              {featureKeys.map((key) => (
                <th key={key} className="text-left p-2 truncate max-w-[100px]">
                  {key}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, idx) => (
              <tr key={idx} className="border-b hover:bg-muted/50">
                <td className="p-2">{idx + 1}</td>
                <td className="p-2">
                  <Badge variant={row.label === 'attack' ? 'destructive' : 'default'}>
                    {row.label}
                  </Badge>
                </td>
                <td className="p-2 text-xs">{row.attackCategory || '-'}</td>
                {featureKeys.map((key) => (
                  <td key={key} className="p-2 font-mono text-xs">
                    {typeof row.features[key] === 'number' 
                      ? row.features[key].toFixed(2) 
                      : row.features[key]
                    }
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </ScrollArea>
    </div>
  );
};

// Training Section Component
const TrainingSection: React.FC<{ 
  dataset: Dataset;
  onPrepare: () => void;
}> = ({ dataset, onPrepare }) => {
  return (
    <div className="space-y-6">
      <div className="bg-muted/50 p-4 rounded-lg">
        <h4 className="font-medium flex items-center gap-2 mb-2">
          <Brain className="h-5 w-5" />
          Prepare for ML Training
        </h4>
        <p className="text-sm text-muted-foreground mb-4">
          This will prepare the dataset for use with the ML pipeline. The data will be:
        </p>
        <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside mb-4">
          <li>Converted to numerical feature vectors</li>
          <li>Normalized using min-max scaling</li>
          <li>Ready for training with C4.5, Random Forest, GBDT, or DT-SVM Hybrid</li>
        </ul>
        
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div className="p-3 bg-background rounded border">
            <div className="text-sm text-muted-foreground">Records</div>
            <div className="text-lg font-bold">{dataset.totalRecords.toLocaleString()}</div>
          </div>
          <div className="p-3 bg-background rounded border">
            <div className="text-sm text-muted-foreground">Features</div>
            <div className="text-lg font-bold">{dataset.featuresCount}</div>
          </div>
        </div>

        <Button onClick={onPrepare} className="w-full">
          <Brain className="h-4 w-4 mr-2" />
          Prepare Dataset for Training
        </Button>
      </div>

      <div className="text-sm text-muted-foreground">
        <p className="font-medium mb-2">After preparation:</p>
        <p>
          Navigate to the <strong>ML Models</strong> tab to train models using this dataset.
          The prepared data will be automatically available for training.
        </p>
      </div>
    </div>
  );
};

export default DatasetManager;
