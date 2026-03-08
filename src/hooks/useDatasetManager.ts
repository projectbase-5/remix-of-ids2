import { useState, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { 
  parseCSVFile, 
  ParsedRecord, 
  DatasetInfo,
  convertToTrainingData,
  getFeatureStatistics
} from '@/lib/datasetParsers';
import { toast } from 'sonner';

export interface Dataset {
  id: string;
  name: string;
  source: string;
  version: string;
  format: string;
  totalRecords: number;
  featuresCount: number;
  labelDistribution: Record<string, number>;
  attackCategories: string[];
  createdAt: string;
  records?: ParsedRecord[];
}

export interface UploadProgress {
  stage: 'parsing' | 'processing' | 'saving' | 'complete' | 'error';
  progress: number;
  message: string;
}

export const useDatasetManager = () => {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [currentDataset, setCurrentDataset] = useState<Dataset | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null);

  // Load datasets from database
  const loadDatasets = useCallback(async () => {
    setIsLoading(true);
    try {
      const { data, error } = await supabase
        .from('datasets')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;

      const formattedDatasets: Dataset[] = (data || []).map(d => ({
        id: d.id,
        name: d.name,
        source: d.source,
        version: d.version,
        format: d.description || 'CUSTOM',
        totalRecords: d.total_records || 0,
        featuresCount: d.features_count || 0,
        labelDistribution: {},
        attackCategories: [],
        createdAt: d.created_at
      }));

      setDatasets(formattedDatasets);
    } catch (error) {
      console.error('Error loading datasets:', error);
      toast.error('Failed to load datasets');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Upload and parse CSV file
  const uploadCSV = useCallback(async (file: File): Promise<Dataset | null> => {
    setUploadProgress({ stage: 'parsing', progress: 0, message: 'Reading file...' });
    
    try {
      // Parse CSV file
      const { records, info } = await parseCSVFile(file, (progress) => {
        setUploadProgress({ 
          stage: 'parsing', 
          progress, 
          message: `Parsing records... ${progress}%` 
        });
      });

      if (records.length === 0) {
        throw new Error('No valid records found in file');
      }

      setUploadProgress({ 
        stage: 'processing', 
        progress: 50, 
        message: 'Processing features...' 
      });

      // Calculate statistics
      const stats = getFeatureStatistics(records);
      console.log('Dataset statistics:', stats);

      setUploadProgress({ 
        stage: 'saving', 
        progress: 75, 
        message: 'Saving to database...' 
      });

      // Save dataset metadata to database
      const { data: datasetData, error: datasetError } = await supabase
        .from('datasets')
        .insert({
          name: info.name.replace(/\.[^/.]+$/, ''), // Remove file extension
          source: 'file_upload',
          version: '1.0',
          description: info.format,
          total_records: info.totalRecords,
          features_count: info.featuresCount
        })
        .select()
        .single();

      if (datasetError) throw datasetError;

      // Save training data records in batches
      const batchSize = 500;
      for (let i = 0; i < records.length; i += batchSize) {
        const batch = records.slice(i, i + batchSize);
        const trainingData = batch.map((record, idx) => ({
          dataset_id: datasetData.id,
          record_id: `${datasetData.id}_${i + idx}`,
          features: record.features,
          label: record.label,
          attack_category: record.attackCategory,
          severity: record.label === 'attack' ? 2 : 1,
          processed_features: null
        }));

        const { error: insertError } = await supabase
          .from('training_data')
          .insert(trainingData);

        if (insertError) {
          console.error('Error inserting batch:', insertError);
        }

        setUploadProgress({ 
          stage: 'saving', 
          progress: 75 + Math.round((i / records.length) * 25), 
          message: `Saving records... ${Math.round(((i + batch.length) / records.length) * 100)}%` 
        });
      }

      const newDataset: Dataset = {
        id: datasetData.id,
        name: info.name.replace(/\.[^/.]+$/, ''),
        source: 'file_upload',
        version: '1.0',
        format: info.format,
        totalRecords: info.totalRecords,
        featuresCount: info.featuresCount,
        labelDistribution: info.labelDistribution,
        attackCategories: info.attackCategories,
        createdAt: datasetData.created_at,
        records
      };

      setDatasets(prev => [newDataset, ...prev]);
      setCurrentDataset(newDataset);
      
      setUploadProgress({ 
        stage: 'complete', 
        progress: 100, 
        message: 'Upload complete!' 
      });

      toast.success(`Dataset "${info.name}" uploaded successfully with ${info.totalRecords} records`);
      
      return newDataset;
    } catch (error) {
      console.error('Error uploading dataset:', error);
      setUploadProgress({ 
        stage: 'error', 
        progress: 0, 
        message: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` 
      });
      toast.error(`Failed to upload dataset: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return null;
    }
  }, []);

  // Load training data for a dataset
  const loadTrainingData = useCallback(async (datasetId: string): Promise<ParsedRecord[]> => {
    try {
      const { data, error } = await supabase
        .from('training_data')
        .select('*')
        .eq('dataset_id', datasetId)
        .limit(10000); // Limit for performance

      if (error) throw error;

      return (data || []).map(row => ({
        features: row.features as Record<string, number>,
        label: row.label,
        attackCategory: row.attack_category || undefined,
        rawData: row.features as Record<string, string | number>
      }));
    } catch (error) {
      console.error('Error loading training data:', error);
      toast.error('Failed to load training data');
      return [];
    }
  }, []);

  // Get prepared training data for ML pipeline
  const getTrainingDataForML = useCallback(async (datasetId: string): Promise<{
    features: number[][];
    labels: string[];
  } | null> => {
    try {
      const records = await loadTrainingData(datasetId);
      if (records.length === 0) return null;
      
      return convertToTrainingData(records);
    } catch (error) {
      console.error('Error preparing training data:', error);
      return null;
    }
  }, [loadTrainingData]);

  // Delete a dataset
  const deleteDataset = useCallback(async (datasetId: string) => {
    try {
      // Delete training data first
      await supabase
        .from('training_data')
        .delete()
        .eq('dataset_id', datasetId);

      // Then delete dataset
      const { error } = await supabase
        .from('datasets')
        .delete()
        .eq('id', datasetId);

      if (error) throw error;

      setDatasets(prev => prev.filter(d => d.id !== datasetId));
      if (currentDataset?.id === datasetId) {
        setCurrentDataset(null);
      }

      toast.success('Dataset deleted successfully');
    } catch (error) {
      console.error('Error deleting dataset:', error);
      toast.error('Failed to delete dataset');
    }
  }, [currentDataset]);

  // Select a dataset as current
  const selectDataset = useCallback(async (datasetId: string) => {
    const dataset = datasets.find(d => d.id === datasetId);
    if (dataset) {
      setCurrentDataset(dataset);
      
      // Load records if not already loaded
      if (!dataset.records) {
        const records = await loadTrainingData(datasetId);
        const updatedDataset = { ...dataset, records };
        setCurrentDataset(updatedDataset);
        setDatasets(prev => prev.map(d => d.id === datasetId ? updatedDataset : d));
      }
    }
  }, [datasets, loadTrainingData]);

  // Get dataset statistics
  const getDatasetStats = useCallback((dataset: Dataset) => {
    const { labelDistribution, totalRecords, featuresCount, attackCategories } = dataset;
    
    const normalCount = labelDistribution['normal'] || 0;
    const attackCount = labelDistribution['attack'] || 0;
    const normalPercentage = totalRecords > 0 ? (normalCount / totalRecords * 100).toFixed(1) : 0;
    const attackPercentage = totalRecords > 0 ? (attackCount / totalRecords * 100).toFixed(1) : 0;
    
    return {
      totalRecords,
      featuresCount,
      normalCount,
      attackCount,
      normalPercentage,
      attackPercentage,
      attackCategories,
      isBalanced: Math.abs(normalCount - attackCount) < totalRecords * 0.1
    };
  }, []);

  return {
    datasets,
    currentDataset,
    isLoading,
    uploadProgress,
    loadDatasets,
    uploadCSV,
    loadTrainingData,
    getTrainingDataForML,
    deleteDataset,
    selectDataset,
    getDatasetStats,
    setUploadProgress
  };
};
