-- Create tables for ML models, training data, and evaluation metrics

-- Dataset management for CICIDS2017, UNSW-NB15, CSE-CIC-IDS2018
CREATE TABLE public.datasets (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  source TEXT NOT NULL, -- 'CICIDS2017', 'UNSW-NB15', 'CSE-CIC-IDS2018'
  version TEXT NOT NULL DEFAULT '1.0',
  description TEXT,
  file_path TEXT,
  total_records INTEGER DEFAULT 0,
  features_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Training data with feature vectors
CREATE TABLE public.training_data (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  dataset_id UUID REFERENCES public.datasets(id) ON DELETE CASCADE,
  record_id TEXT NOT NULL,
  features JSONB NOT NULL, -- Original features
  processed_features JSONB, -- After preprocessing/normalization
  label TEXT NOT NULL, -- 'BENIGN', 'DoS', 'DDoS', 'PortScan', 'Bot', etc.
  attack_category TEXT, -- 'DoS', 'Probe', 'R2L', 'U2R', 'Normal'
  severity INTEGER DEFAULT 1, -- 1-5 severity scale
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- ML models registry
CREATE TABLE public.ml_models (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  algorithm TEXT NOT NULL, -- 'C4.5', 'RandomForest', 'GBDT', 'DT_SVM_Hybrid'
  version TEXT NOT NULL DEFAULT '1.0',
  model_config JSONB NOT NULL, -- Hyperparameters
  model_artifacts JSONB, -- Serialized model or reference
  training_dataset_id UUID REFERENCES public.datasets(id),
  feature_importance JSONB, -- Feature importance scores
  status TEXT NOT NULL DEFAULT 'training', -- 'training', 'ready', 'deprecated'
  is_active BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Model evaluation metrics
CREATE TABLE public.model_evaluations (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  model_id UUID REFERENCES public.ml_models(id) ON DELETE CASCADE,
  evaluation_type TEXT NOT NULL, -- 'training', 'validation', 'testing'
  dataset_id UUID REFERENCES public.datasets(id),
  accuracy DECIMAL(5,4),
  precision DECIMAL(5,4),
  recall DECIMAL(5,4),
  f1_score DECIMAL(5,4),
  false_positive_rate DECIMAL(5,4),
  detection_rate DECIMAL(5,4),
  training_time_ms INTEGER,
  testing_time_ms INTEGER,
  confusion_matrix JSONB,
  roc_auc DECIMAL(5,4),
  class_performance JSONB, -- Per-class metrics
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Feature engineering and preprocessing metadata
CREATE TABLE public.feature_engineering (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  dataset_id UUID REFERENCES public.datasets(id) ON DELETE CASCADE,
  preprocessing_steps JSONB NOT NULL, -- PCA, SVD, normalization steps
  feature_selection JSONB, -- Selected features after PCA/SVD
  smote_config JSONB, -- SMOTE parameters for class balancing
  normalization_params JSONB, -- Min-max, z-score parameters
  original_features INTEGER,
  processed_features INTEGER,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Real-time predictions log
CREATE TABLE public.predictions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  model_id UUID REFERENCES public.ml_models(id),
  network_event_id UUID, -- Reference to network events
  features JSONB NOT NULL,
  prediction TEXT NOT NULL, -- Predicted class
  confidence DECIMAL(5,4),
  prediction_time_ms INTEGER,
  is_anomaly BOOLEAN DEFAULT false,
  actual_label TEXT, -- For feedback learning
  feedback_provided BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- IoT/5G adaptive learning configurations
CREATE TABLE public.adaptive_configs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  environment_type TEXT NOT NULL, -- 'IoT', '5G', 'Edge', 'Cloud'
  model_id UUID REFERENCES public.ml_models(id),
  resource_constraints JSONB, -- Memory, CPU, bandwidth limits
  update_frequency INTEGER DEFAULT 3600, -- Seconds between model updates
  batch_size INTEGER DEFAULT 100,
  learning_rate DECIMAL(6,5) DEFAULT 0.001,
  drift_threshold DECIMAL(5,4) DEFAULT 0.05,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Attack pattern analysis
CREATE TABLE public.attack_patterns (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  pattern_name TEXT NOT NULL,
  attack_type TEXT NOT NULL,
  feature_signature JSONB NOT NULL,
  confidence_threshold DECIMAL(5,4) DEFAULT 0.8,
  detection_rules JSONB,
  evasion_techniques JSONB,
  countermeasures JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE public.datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.training_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ml_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.model_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feature_engineering ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.predictions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.adaptive_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_patterns ENABLE ROW LEVEL SECURITY;

-- Create policies for public access (since this is a demo/research system)
CREATE POLICY "Enable read access for all users" ON public.datasets FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.datasets FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.datasets FOR UPDATE USING (true);

CREATE POLICY "Enable read access for all users" ON public.training_data FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.training_data FOR INSERT WITH CHECK (true);

CREATE POLICY "Enable read access for all users" ON public.ml_models FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.ml_models FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.ml_models FOR UPDATE USING (true);

CREATE POLICY "Enable read access for all users" ON public.model_evaluations FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.model_evaluations FOR INSERT WITH CHECK (true);

CREATE POLICY "Enable read access for all users" ON public.feature_engineering FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.feature_engineering FOR INSERT WITH CHECK (true);

CREATE POLICY "Enable read access for all users" ON public.predictions FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.predictions FOR INSERT WITH CHECK (true);

CREATE POLICY "Enable read access for all users" ON public.adaptive_configs FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.adaptive_configs FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.adaptive_configs FOR UPDATE USING (true);

CREATE POLICY "Enable read access for all users" ON public.attack_patterns FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.attack_patterns FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.attack_patterns FOR UPDATE USING (true);

-- Create indexes for performance
CREATE INDEX idx_training_data_dataset_id ON public.training_data(dataset_id);
CREATE INDEX idx_training_data_label ON public.training_data(label);
CREATE INDEX idx_training_data_attack_category ON public.training_data(attack_category);
CREATE INDEX idx_ml_models_algorithm ON public.ml_models(algorithm);
CREATE INDEX idx_ml_models_status ON public.ml_models(status);
CREATE INDEX idx_model_evaluations_model_id ON public.model_evaluations(model_id);
CREATE INDEX idx_predictions_model_id ON public.predictions(model_id);
CREATE INDEX idx_predictions_created_at ON public.predictions(created_at);
CREATE INDEX idx_adaptive_configs_environment ON public.adaptive_configs(environment_type);

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_datasets_updated_at
  BEFORE UPDATE ON public.datasets
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_ml_models_updated_at
  BEFORE UPDATE ON public.ml_models
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_adaptive_configs_updated_at
  BEFORE UPDATE ON public.adaptive_configs
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_attack_patterns_updated_at
  BEFORE UPDATE ON public.attack_patterns
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();