import { Matrix } from 'ml-matrix';
import { RandomForestClassifier as RFClassifier } from 'ml-random-forest';

export interface DecisionNode {
  feature?: number;
  threshold?: number;
  left?: DecisionNode;
  right?: DecisionNode;
  label?: number;
  samples?: number;
  impurity?: number;
}

export interface Classifier {
  train(X: number[][], y: number[]): void;
  predict(X: number[][]): number[];
}

// C4.5 Decision Tree Implementation
export class C45DecisionTree implements Classifier {
  private root: DecisionNode | null = null;
  private maxDepth: number;
  private minSamplesSplit: number;
  private classes: number[] = [];

  constructor(maxDepth: number = 10, minSamplesSplit: number = 2) {
    this.maxDepth = maxDepth;
    this.minSamplesSplit = minSamplesSplit;
  }

  train(X: number[][], y: number[]): void {
    this.classes = Array.from(new Set(y)).sort();
    this.root = this.buildTree(X, y, 0);
  }

  predict(X: number[][]): number[] {
    return X.map(sample => this.predictSingle(sample));
  }

  private predictSingle(sample: number[]): number {
    let node = this.root;
    while (node && node.feature !== undefined) {
      if (sample[node.feature] <= (node.threshold || 0)) {
        node = node.left || null;
      } else {
        node = node.right || null;
      }
    }
    return node?.label ?? this.classes[0];
  }

  private buildTree(X: number[][], y: number[], depth: number): DecisionNode {
    const uniqueLabels = Array.from(new Set(y));
    
    // Stopping conditions
    if (uniqueLabels.length === 1 || depth >= this.maxDepth || X.length < this.minSamplesSplit) {
      return { label: this.majorityClass(y), samples: X.length };
    }

    const { feature, threshold, gain } = this.findBestSplit(X, y);
    
    if (gain === 0) {
      return { label: this.majorityClass(y), samples: X.length };
    }

    const [leftX, leftY, rightX, rightY] = this.splitData(X, y, feature, threshold);
    
    return {
      feature,
      threshold,
      left: this.buildTree(leftX, leftY, depth + 1),
      right: this.buildTree(rightX, rightY, depth + 1),
      samples: X.length
    };
  }

  private findBestSplit(X: number[][], y: number[]): { feature: number; threshold: number; gain: number } {
    let bestGain = 0;
    let bestFeature = 0;
    let bestThreshold = 0;

    const numFeatures = X[0].length;
    
    for (let feature = 0; feature < numFeatures; feature++) {
      const values = X.map(row => row[feature]);
      const uniqueValues = Array.from(new Set(values)).sort((a, b) => a - b);
      
      for (let i = 0; i < uniqueValues.length - 1; i++) {
        const threshold = (uniqueValues[i] + uniqueValues[i + 1]) / 2;
        const gain = this.informationGain(X, y, feature, threshold);
        
        if (gain > bestGain) {
          bestGain = gain;
          bestFeature = feature;
          bestThreshold = threshold;
        }
      }
    }

    return { feature: bestFeature, threshold: bestThreshold, gain: bestGain };
  }

  private informationGain(X: number[][], y: number[], feature: number, threshold: number): number {
    const parentEntropy = this.entropy(y);
    const [, leftY, , rightY] = this.splitData(X, y, feature, threshold);
    
    if (leftY.length === 0 || rightY.length === 0) return 0;
    
    const n = y.length;
    const leftEntropy = this.entropy(leftY);
    const rightEntropy = this.entropy(rightY);
    const childEntropy = (leftY.length / n) * leftEntropy + (rightY.length / n) * rightEntropy;
    
    return parentEntropy - childEntropy;
  }

  private entropy(y: number[]): number {
    const counts = new Map<number, number>();
    y.forEach(label => counts.set(label, (counts.get(label) || 0) + 1));
    
    const n = y.length;
    let entropy = 0;
    
    counts.forEach(count => {
      const p = count / n;
      entropy -= p * Math.log2(p);
    });
    
    return entropy;
  }

  private splitData(X: number[][], y: number[], feature: number, threshold: number): [number[][], number[], number[][], number[]] {
    const leftX: number[][] = [];
    const leftY: number[] = [];
    const rightX: number[][] = [];
    const rightY: number[] = [];
    
    X.forEach((sample, i) => {
      if (sample[feature] <= threshold) {
        leftX.push(sample);
        leftY.push(y[i]);
      } else {
        rightX.push(sample);
        rightY.push(y[i]);
      }
    });
    
    return [leftX, leftY, rightX, rightY];
  }

  private majorityClass(y: number[]): number {
    const counts = new Map<number, number>();
    y.forEach(label => counts.set(label, (counts.get(label) || 0) + 1));
    
    let maxCount = 0;
    let majorityLabel = this.classes[0];
    
    counts.forEach((count, label) => {
      if (count > maxCount) {
        maxCount = count;
        majorityLabel = label;
      }
    });
    
    return majorityLabel;
  }
}

// Gradient Boosted Decision Trees Implementation
export class GradientBoostedTrees implements Classifier {
  private trees: C45DecisionTree[] = [];
  private learningRate: number;
  private numTrees: number;
  private classes: number[] = [];

  constructor(numTrees: number = 50, learningRate: number = 0.1, maxDepth: number = 5) {
    this.numTrees = numTrees;
    this.learningRate = learningRate;
    
    // Initialize trees
    for (let i = 0; i < numTrees; i++) {
      this.trees.push(new C45DecisionTree(maxDepth, 2));
    }
  }

  train(X: number[][], y: number[]): void {
    this.classes = Array.from(new Set(y)).sort();
    const n = X.length;
    
    // Initialize predictions
    let predictions = new Array(n).fill(0);
    
    for (let i = 0; i < this.numTrees; i++) {
      // Calculate pseudo-residuals
      const residuals = y.map((label, idx) => label - predictions[idx]);
      
      // Train tree on residuals
      this.trees[i].train(X, residuals);
      
      // Update predictions
      const treePredictions = this.trees[i].predict(X);
      predictions = predictions.map((pred, idx) => 
        pred + this.learningRate * treePredictions[idx]
      );
    }
  }

  predict(X: number[][]): number[] {
    const predictions = X.map(() => 0);
    
    this.trees.forEach(tree => {
      const treePredictions = tree.predict(X);
      treePredictions.forEach((pred, idx) => {
        predictions[idx] += this.learningRate * pred;
      });
    });
    
    // Convert to class labels
    return predictions.map(pred => Math.round(Math.max(0, Math.min(this.classes.length - 1, pred))));
  }
}

// Decision Tree + SVM Hybrid Implementation
export class DTSVMHybrid implements Classifier {
  private decisionTree: C45DecisionTree;
  private svmWeights: number[] = [];
  private svmBias: number = 0;
  private classes: number[] = [];
  private useSVM: boolean = false;

  constructor(maxDepth: number = 8) {
    this.decisionTree = new C45DecisionTree(maxDepth, 2);
  }

  train(X: number[][], y: number[]): void {
    this.classes = Array.from(new Set(y)).sort();
    
    // First pass: Train decision tree
    this.decisionTree.train(X, y);
    
    // Get tree predictions
    const treePredictions = this.decisionTree.predict(X);
    
    // Find misclassified samples
    const misclassified: number[][] = [];
    const misclassifiedLabels: number[] = [];
    
    treePredictions.forEach((pred, idx) => {
      if (pred !== y[idx]) {
        misclassified.push(X[idx]);
        misclassifiedLabels.push(y[idx]);
      }
    });
    
    // If we have misclassified samples, train SVM on them
    if (misclassified.length > 10) {
      this.useSVM = true;
      this.trainSVM(misclassified, misclassifiedLabels);
    }
  }

  predict(X: number[][]): number[] {
    const treePredictions = this.decisionTree.predict(X);
    
    if (!this.useSVM) {
      return treePredictions;
    }
    
    // Use SVM for refinement
    return treePredictions.map((treePred, idx) => {
      const svmScore = this.svmPredict(X[idx]);
      // Use SVM prediction if confidence is high
      if (Math.abs(svmScore) > 0.5) {
        return svmScore > 0 ? this.classes[1] : this.classes[0];
      }
      return treePred;
    });
  }

  private trainSVM(X: number[][], y: number[]): void {
    const numFeatures = X[0].length;
    this.svmWeights = new Array(numFeatures).fill(0);
    this.svmBias = 0;
    
    const learningRate = 0.01;
    const lambda = 0.01;
    const epochs = 100;
    
    // Simple SGD for linear SVM
    for (let epoch = 0; epoch < epochs; epoch++) {
      X.forEach((sample, idx) => {
        const label = y[idx] === this.classes[1] ? 1 : -1;
        const prediction = this.svmPredict(sample);
        
        if (label * prediction < 1) {
          // Update weights
          this.svmWeights = this.svmWeights.map((w, i) => 
            w - learningRate * (lambda * w - label * sample[i])
          );
          this.svmBias -= learningRate * (-label);
        } else {
          // Regularization only
          this.svmWeights = this.svmWeights.map(w => w - learningRate * lambda * w);
        }
      });
    }
  }

  private svmPredict(sample: number[]): number {
    let score = this.svmBias;
    sample.forEach((value, idx) => {
      score += this.svmWeights[idx] * value;
    });
    return score;
  }
}

export class RandomForestClassifier implements Classifier {
  private model: RFClassifier | null = null;

  constructor(private options = { nEstimators: 50, maxFeatures: 0.5, seed: 42 }) {}

  train(X: number[][], y: number[]): void {
    this.model = new RFClassifier(this.options);
    this.model.train(X, y);
  }

  predict(X: number[][]): number[] {
    if (!this.model) throw new Error('Model not trained');
    return this.model.predict(X);
  }
}
