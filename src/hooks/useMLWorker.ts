import { useRef, useCallback, useEffect, useState } from 'react';

export interface WorkerProgress {
  value: number;
  stage: string;
}

export interface WorkerResult {
  algorithm: string;
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    falsePositiveRate: number;
    detectionRate: number;
    trainingTime: number;
    testingTime: number;
    confusionMatrix: number[][];
  };
}

export const useMLWorker = () => {
  const workerRef = useRef<Worker | null>(null);
  const [progress, setProgress] = useState<WorkerProgress>({ value: 0, stage: '' });
  const [isTraining, setIsTraining] = useState(false);
  const resolveRef = useRef<((result: WorkerResult) => void) | null>(null);
  const rejectRef = useRef<((error: Error) => void) | null>(null);

  const createWorker = useCallback(() => {
    const worker = new Worker(
      new URL('../workers/mlTraining.worker.ts', import.meta.url),
      { type: 'module' }
    );
    worker.onmessage = (e: MessageEvent) => {
      const { type } = e.data;
      if (type === 'progress') {
        setProgress({ value: e.data.value, stage: e.data.stage });
      } else if (type === 'result') {
        setIsTraining(false);
        setProgress({ value: 100, stage: 'Complete' });
        resolveRef.current?.(e.data as WorkerResult);
        resolveRef.current = null;
        rejectRef.current = null;
      } else if (type === 'error') {
        setIsTraining(false);
        setProgress({ value: 0, stage: '' });
        rejectRef.current?.(new Error(e.data.message));
        resolveRef.current = null;
        rejectRef.current = null;
      }
    };
    worker.onerror = (err) => {
      setIsTraining(false);
      rejectRef.current?.(new Error(err.message));
      resolveRef.current = null;
      rejectRef.current = null;
    };
    return worker;
  }, []);

  const trainInWorker = useCallback((algorithm: string, trainingData?: { features: number[][]; labels: string[] }): Promise<WorkerResult> => {
    return new Promise((resolve, reject) => {
      resolveRef.current = resolve;
      rejectRef.current = reject;
      setIsTraining(true);
      setProgress({ value: 0, stage: 'Starting...' });
      // Always create a fresh worker (previous one may have been terminated)
      workerRef.current?.terminate();
      const worker = createWorker();
      workerRef.current = worker;
      worker.postMessage({ type: 'train', algorithm, trainingData });
    });
  }, [createWorker]);

  const cancelTraining = useCallback(() => {
    if (workerRef.current) {
      workerRef.current.terminate();
      workerRef.current = null;
    }
    setIsTraining(false);
    setProgress({ value: 0, stage: '' });
    rejectRef.current?.(new Error('Training cancelled'));
    resolveRef.current = null;
    rejectRef.current = null;
  }, []);

  useEffect(() => {
    return () => {
      workerRef.current?.terminate();
      workerRef.current = null;
    };
  }, []);

  return { trainInWorker, cancelTraining, progress, isTraining };
};
