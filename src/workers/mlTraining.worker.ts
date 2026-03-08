import { PCA } from 'ml-pca';
import { 
  C45DecisionTree, 
  GradientBoostedTrees, 
  DTSVMHybrid, 
  RandomForestClassifier,
  Classifier 
} from '@/lib/mlAlgorithms';

// ---- Data generation ----

function generateSyntheticData() {
  const attackTypes = ['BENIGN', 'DoS', 'DDoS', 'PortScan', 'Bot', 'FTP-Patator', 'SSH-Patator', 'Infiltration'];
  const syntheticData = [];

  for (let i = 0; i < 200; i++) {
    const isAttack = Math.random() > 0.7;
    const label = isAttack ? attackTypes[Math.floor(Math.random() * (attackTypes.length - 1)) + 1] : 'BENIGN';
    
    syntheticData.push({
      features: {
        duration: Math.random() * 1000,
        protocol_type: Math.random() > 0.5 ? 'tcp' : 'udp',
        service: 'http',
        flag: 'SF',
        src_bytes: Math.floor(Math.random() * 10000),
        dst_bytes: Math.floor(Math.random() * 10000),
        land: Math.random() > 0.95 ? 1 : 0,
        wrong_fragment: Math.random() > 0.98 ? 1 : 0,
        urgent: Math.random() > 0.99 ? 1 : 0,
        hot: Math.floor(Math.random() * 10),
        num_failed_logins: Math.floor(Math.random() * 5),
        logged_in: Math.random() > 0.3 ? 1 : 0,
        num_compromised: isAttack ? Math.floor(Math.random() * 3) : 0,
        root_shell: isAttack ? (Math.random() > 0.8 ? 1 : 0) : 0,
        su_attempted: isAttack ? (Math.random() > 0.9 ? 1 : 0) : 0,
        num_root: isAttack ? Math.floor(Math.random() * 2) : 0,
        num_file_creations: Math.floor(Math.random() * 5),
        num_shells: isAttack ? Math.floor(Math.random() * 2) : 0,
        num_access_files: Math.floor(Math.random() * 3),
        num_outbound_cmds: 0,
        is_host_login: Math.random() > 0.8 ? 1 : 0,
        is_guest_login: Math.random() > 0.9 ? 1 : 0,
        count: Math.floor(Math.random() * 100) + 1,
        srv_count: Math.floor(Math.random() * 50) + 1,
        serror_rate: Math.random(),
        srv_serror_rate: Math.random(),
        rerror_rate: Math.random(),
        srv_rerror_rate: Math.random(),
        same_srv_rate: Math.random(),
        diff_srv_rate: Math.random(),
        srv_diff_host_rate: Math.random(),
        dst_host_count: Math.floor(Math.random() * 255) + 1,
        dst_host_srv_count: Math.floor(Math.random() * 100) + 1,
        dst_host_same_srv_rate: Math.random(),
        dst_host_diff_srv_rate: Math.random(),
        dst_host_same_src_port_rate: Math.random(),
        dst_host_srv_diff_host_rate: Math.random(),
        dst_host_serror_rate: Math.random(),
        dst_host_srv_serror_rate: Math.random(),
        dst_host_rerror_rate: Math.random(),
        dst_host_srv_rerror_rate: Math.random()
      },
      label
    });
  }
  return syntheticData;
}

// ---- Feature extraction ----

function extractFeatureVector(features: any): number[] {
  const protocolMap: Record<string, number> = { tcp: 1, udp: 2, icmp: 3 };
  const serviceMap: Record<string, number> = { http: 1, ftp: 2, smtp: 3, ssh: 4, telnet: 5, other: 6 };
  const flagMap: Record<string, number> = { SF: 1, S0: 2, REJ: 3, RSTR: 4, SH: 5, other: 6 };

  return [
    features.duration,
    protocolMap[features.protocol_type] || 0,
    serviceMap[features.service] || 6,
    flagMap[features.flag] || 6,
    features.src_bytes, features.dst_bytes, features.land, features.wrong_fragment,
    features.urgent, features.hot, features.num_failed_logins, features.logged_in,
    features.num_compromised, features.root_shell, features.su_attempted, features.num_root,
    features.num_file_creations, features.num_shells, features.num_access_files,
    features.num_outbound_cmds, features.is_host_login, features.is_guest_login,
    features.count, features.srv_count, features.serror_rate, features.srv_serror_rate,
    features.rerror_rate, features.srv_rerror_rate, features.same_srv_rate,
    features.diff_srv_rate, features.srv_diff_host_rate, features.dst_host_count,
    features.dst_host_srv_count, features.dst_host_same_srv_rate, features.dst_host_diff_srv_rate,
    features.dst_host_same_src_port_rate, features.dst_host_srv_diff_host_rate,
    features.dst_host_serror_rate, features.dst_host_srv_serror_rate,
    features.dst_host_rerror_rate, features.dst_host_srv_rerror_rate
  ];
}

// ---- Normalization ----

function normalizeFeatures(features: number[][]): number[][] {
  const numFeatures = features[0].length;
  const mins = new Array(numFeatures).fill(Infinity);
  const maxs = new Array(numFeatures).fill(-Infinity);

  features.forEach(sample => {
    sample.forEach((value, index) => {
      mins[index] = Math.min(mins[index], value);
      maxs[index] = Math.max(maxs[index], value);
    });
  });

  return features.map(sample =>
    sample.map((value, index) => {
      const range = maxs[index] - mins[index];
      return range === 0 ? 0 : (value - mins[index]) / range;
    })
  );
}

// ---- SMOTE ----

function applySMOTE(features: number[][], labels: string[], ratio: number) {
  const labelCounts: Record<string, number> = {};
  labels.forEach(l => { labelCounts[l] = (labelCounts[l] || 0) + 1; });

  const maxCount = Math.max(...Object.values(labelCounts));
  const syntheticFeatures: number[][] = [];
  const syntheticLabels: string[] = [];

  Object.entries(labelCounts).forEach(([label, count]) => {
    if (count < maxCount * ratio) {
      const classFeatures = features.filter((_, i) => labels[i] === label);
      const synthCount = Math.floor(maxCount * ratio) - count;
      for (let i = 0; i < synthCount; i++) {
        if (classFeatures.length < 2) { syntheticFeatures.push(classFeatures[0]); }
        else {
          const s1 = classFeatures[Math.floor(Math.random() * classFeatures.length)];
          const s2 = classFeatures[Math.floor(Math.random() * classFeatures.length)];
          const alpha = Math.random();
          syntheticFeatures.push(s1.map((v, j) => v + alpha * (s2[j] - v)));
        }
        syntheticLabels.push(label);
      }
    }
  });

  return { features: [...features, ...syntheticFeatures], labels: [...labels, ...syntheticLabels] };
}

// ---- Metrics ----

function calculateMetrics(trueLabels: string[], predictions: string[]) {
  const classes = [...new Set(trueLabels)];
  const matrix = classes.map(() => new Array(classes.length).fill(0));
  trueLabels.forEach((tl, i) => {
    const ti = classes.indexOf(tl);
    const pi = classes.indexOf(predictions[i]);
    if (ti >= 0 && pi >= 0) matrix[ti][pi]++;
  });

  let totalCorrect = 0;
  for (let i = 0; i < classes.length; i++) totalCorrect += matrix[i][i];
  const accuracy = totalCorrect / trueLabels.length;

  let avgPrecision = 0, avgRecall = 0, avgF1 = 0, fp = 0, tp = 0;
  classes.forEach((_, i) => {
    const tpi = matrix[i][i];
    const fpi = matrix.reduce((a, row, j) => a + (j !== i ? row[i] : 0), 0);
    const fni = matrix[i].reduce((a, v, j) => a + (j !== i ? v : 0), 0);
    const prec = tpi / (tpi + fpi) || 0;
    const rec = tpi / (tpi + fni) || 0;
    const f1 = 2 * (prec * rec) / (prec + rec) || 0;
    avgPrecision += prec; avgRecall += rec; avgF1 += f1;
    fp += fpi; tp += tpi;
  });
  avgPrecision /= classes.length;
  avgRecall /= classes.length;
  avgF1 /= classes.length;

  return {
    accuracy, precision: avgPrecision, recall: avgRecall, f1Score: avgF1,
    falsePositiveRate: fp / (fp + tp), detectionRate: avgRecall,
    confusionMatrix: matrix
  };
}

// ---- Main handler ----

self.onmessage = (e: MessageEvent) => {
  const { type, algorithm, trainingData } = e.data;
  if (type !== 'train') return;

  try {
    let features: number[][];
    let labels: string[];

    if (trainingData && trainingData.features && trainingData.features.length > 0) {
      // Use real training data passed from main thread
      self.postMessage({ type: 'progress', value: 10, stage: 'Using live data...' });
      features = trainingData.features;
      labels = trainingData.labels;
    } else {
      // Fall back to synthetic data generation
      self.postMessage({ type: 'progress', value: 10, stage: 'Generating synthetic data...' });
      const rawData = generateSyntheticData();
      features = rawData.map(d => extractFeatureVector(d.features));
      labels = rawData.map(d => d.label);
    }

    // Step 2: Normalize
    self.postMessage({ type: 'progress', value: 25, stage: 'Preprocessing...' });
    let normalized = normalizeFeatures(features);

    // Step 3: PCA
    self.postMessage({ type: 'progress', value: 40, stage: 'PCA reduction...' });
    try {
      const pca = new PCA(normalized);
      pca.predict(normalized, { nComponents: 10 });
    } catch { /* PCA optional */ }

    // Step 4: SMOTE
    self.postMessage({ type: 'progress', value: 50, stage: 'Balancing classes...' });
    const balanced = applySMOTE(normalized, labels, 1.0);

    // Step 5: Train
    self.postMessage({ type: 'progress', value: 60, stage: `Training ${algorithm}...` });
    const startTime = Date.now();

    let classifier: Classifier;
    switch (algorithm) {
      case 'C4.5': classifier = new C45DecisionTree(10, 2); break;
      case 'GBDT': classifier = new GradientBoostedTrees(50, 0.1, 5); break;
      case 'DT_SVM_Hybrid': classifier = new DTSVMHybrid(8); break;
      case 'RandomForest':
      default: classifier = new RandomForestClassifier({ nEstimators: 50, maxFeatures: 0.5, seed: 42 }); break;
    }

    const splitIndex = Math.floor(balanced.features.length * 0.8);
    const trainFeatures = balanced.features.slice(0, splitIndex);
    const trainLabels = balanced.labels.slice(0, splitIndex);
    const testFeatures = balanced.features.slice(splitIndex);
    const testLabels = balanced.labels.slice(splitIndex);

    const uniqueLabels = [...new Set(balanced.labels)];
    const labelToIndex = Object.fromEntries(uniqueLabels.map((l, i) => [l, i]));
    const indexToLabel = Object.fromEntries(uniqueLabels.map((l, i) => [i, l]));

    const numericTrainLabels = trainLabels.map(l => labelToIndex[l]);
    classifier.train(trainFeatures, numericTrainLabels);
    const trainingTime = Date.now() - startTime;

    // Step 6: Evaluate
    self.postMessage({ type: 'progress', value: 85, stage: 'Evaluating...' });
    const testStart = Date.now();
    const numericPreds = classifier.predict(testFeatures);
    const predictions = numericPreds.map(p => indexToLabel[p]);
    const testingTime = Date.now() - testStart;

    const metrics = calculateMetrics(testLabels, predictions);

    self.postMessage({ type: 'progress', value: 95, stage: 'Done' });

    // Step 7: Return results
    self.postMessage({
      type: 'result',
      algorithm,
      metrics: {
        ...metrics,
        trainingTime,
        testingTime
      }
    });
  } catch (error: any) {
    self.postMessage({ type: 'error', message: error?.message || 'Training failed' });
  }
};
