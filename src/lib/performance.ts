/**
 * Performance utilities for debouncing, throttling, and optimizing renders
 */

/**
 * Debounce function - delays execution until after wait time has elapsed since last call
 * Useful for search inputs, resize handlers, etc.
 */
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: ReturnType<typeof setTimeout> | null = null;

  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null;
      func(...args);
    };

    if (timeout) {
      clearTimeout(timeout);
    }
    timeout = setTimeout(later, wait);
  };
}

/**
 * Throttle function - ensures function is called at most once per specified time period
 * Useful for scroll handlers, mouse move, etc.
 */
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean;
  
  return function executedFunction(...args: Parameters<T>) {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

/**
 * RequestAnimationFrame wrapper for smooth animations
 */
export function rafThrottle<T extends (...args: any[]) => any>(
  func: T
): (...args: Parameters<T>) => void {
  let rafId: number | null = null;

  return function executedFunction(...args: Parameters<T>) {
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
    }
    
    rafId = requestAnimationFrame(() => {
      func(...args);
      rafId = null;
    });
  };
}

/**
 * Measure component render time (development only)
 */
export function measureRenderTime(componentName: string, callback: () => void) {
  if (import.meta.env.DEV) {
    const start = performance.now();
    callback();
    const end = performance.now();
    console.log(`[Performance] ${componentName} rendered in ${(end - start).toFixed(2)}ms`);
  } else {
    callback();
  }
}

/**
 * Check if device is low-end based on available metrics
 */
export function isLowEndDevice(): boolean {
  // Check hardware concurrency (CPU cores)
  const cores = navigator.hardwareConcurrency || 1;
  
  // Check device memory if available (in GB)
  const memory = (navigator as any).deviceMemory || 4;
  
  // Consider device low-end if it has 2 or fewer cores or 2GB or less RAM
  return cores <= 2 || memory <= 2;
}

/**
 * Get optimal refresh rate based on device capabilities
 */
export function getOptimalRefreshRate(): {
  eventGeneration: number;
  metricsUpdate: number;
  chartUpdate: number;
} {
  const isLowEnd = isLowEndDevice();
  
  return {
    eventGeneration: isLowEnd ? 500 : 300,
    metricsUpdate: isLowEnd ? 2000 : 1000,
    chartUpdate: isLowEnd ? 1000 : 500,
  };
}

/**
 * Batch updates using requestIdleCallback for better performance
 */
export function batchUpdate(callback: () => void, options?: IdleRequestOptions) {
  if ('requestIdleCallback' in window) {
    requestIdleCallback(callback, options);
  } else {
    // Fallback to setTimeout
    setTimeout(callback, 1);
  }
}
