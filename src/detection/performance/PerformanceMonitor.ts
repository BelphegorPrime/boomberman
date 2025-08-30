/**
 * Performance monitoring and benchmarking for detection system
 */
export class PerformanceMonitor {
    private metrics: Map<string, PerformanceMetric> = new Map();
    private benchmarks: Map<string, BenchmarkResult> = new Map();
    private readonly maxMetrics: number;

    constructor(maxMetrics = 10000) {
        this.maxMetrics = maxMetrics;
    }

    /**
     * Start timing an operation
     */
    startTiming(operationName: string): PerformanceTimer {
        return new PerformanceTimer(operationName, this);
    }

    /**
     * Record a performance metric
     */
    recordMetric(name: string, duration: number, metadata?: Record<string, any>): void {
        let metric = this.metrics.get(name);

        if (!metric) {
            metric = {
                name,
                count: 0,
                totalDuration: 0,
                minDuration: Infinity,
                maxDuration: 0,
                avgDuration: 0,
                p95Duration: 0,
                p99Duration: 0,
                durations: [],
                metadata: metadata || {}
            };
            this.metrics.set(name, metric);
        }

        // Update metric
        metric.count++;
        metric.totalDuration += duration;
        metric.minDuration = Math.min(metric.minDuration, duration);
        metric.maxDuration = Math.max(metric.maxDuration, duration);
        metric.avgDuration = metric.totalDuration / metric.count;

        // Store duration for percentile calculation (keep last 1000)
        metric.durations.push(duration);
        if (metric.durations.length > 1000) {
            metric.durations = metric.durations.slice(-1000);
        }

        // Only calculate percentiles every 1000 recordings to reduce overhead
        if (metric.count % 1000 === 0) {
            this.updatePercentiles(metric);
        }

        // Cleanup old metrics if we have too many
        if (this.metrics.size > this.maxMetrics) {
            const oldestKey = this.metrics.keys().next().value;
            if (oldestKey) {
                this.metrics.delete(oldestKey);
            }
        }
    }

    /**
     * Run a benchmark comparing two functions
     */
    async benchmark<T>(
        name: string,
        originalFn: () => Promise<T> | T,
        optimizedFn: () => Promise<T> | T,
        iterations = 1000
    ): Promise<BenchmarkResult> {
        console.log(`Running benchmark: ${name} (${iterations} iterations)`);

        // Warm up
        for (let i = 0; i < 10; i++) {
            await originalFn();
            await optimizedFn();
        }

        // Benchmark original function
        const originalTimes: number[] = [];
        for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            await originalFn();
            const end = performance.now();
            originalTimes.push(end - start);
        }

        // Benchmark optimized function
        const optimizedTimes: number[] = [];
        for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            await optimizedFn();
            const end = performance.now();
            optimizedTimes.push(end - start);
        }

        // Calculate statistics
        const originalStats = this.calculateStats(originalTimes);
        const optimizedStats = this.calculateStats(optimizedTimes);

        const result: BenchmarkResult = {
            name,
            iterations,
            original: originalStats,
            optimized: optimizedStats,
            improvement: {
                avgSpeedup: originalStats.avg / optimizedStats.avg,
                medianSpeedup: originalStats.median / optimizedStats.median,
                p95Speedup: originalStats.p95 / optimizedStats.p95,
                p99Speedup: originalStats.p99 / optimizedStats.p99
            },
            timestamp: Date.now()
        };

        this.benchmarks.set(name, result);
        console.log(`Benchmark ${name} completed. Average speedup: ${result.improvement.avgSpeedup.toFixed(2)}x`);

        return result;
    }

    /**
     * Get performance metrics for a specific operation
     */
    getMetric(name: string): PerformanceMetric | undefined {
        return this.metrics.get(name);
    }

    /**
     * Get all performance metrics
     */
    getAllMetrics(): PerformanceMetric[] {
        return Array.from(this.metrics.values());
    }

    /**
     * Get benchmark results
     */
    getBenchmark(name: string): BenchmarkResult | undefined {
        return this.benchmarks.get(name);
    }

    /**
     * Get all benchmark results
     */
    getAllBenchmarks(): BenchmarkResult[] {
        return Array.from(this.benchmarks.values());
    }

    /**
     * Get performance summary
     */
    getSummary(): PerformanceSummary {
        const metrics = this.getAllMetrics();
        const benchmarks = this.getAllBenchmarks();

        const totalOperations = metrics.reduce((sum, m) => sum + m.count, 0);
        const avgDuration = metrics.length > 0 ?
            metrics.reduce((sum, m) => sum + m.avgDuration, 0) / metrics.length : 0;

        const slowestOperations = metrics
            .sort((a, b) => b.avgDuration - a.avgDuration)
            .slice(0, 5);

        const fastestOperations = metrics
            .sort((a, b) => a.avgDuration - b.avgDuration)
            .slice(0, 5);

        return {
            totalOperations,
            totalMetrics: metrics.length,
            avgDuration,
            slowestOperations,
            fastestOperations,
            benchmarks: benchmarks.length,
            lastUpdated: Date.now()
        };
    }

    /**
     * Clear all metrics and benchmarks
     */
    clear(): void {
        this.metrics.clear();
        this.benchmarks.clear();
    }

    /**
     * Export metrics to JSON
     */
    exportMetrics(): string {
        return JSON.stringify({
            metrics: Array.from(this.metrics.entries()),
            benchmarks: Array.from(this.benchmarks.entries()),
            timestamp: Date.now()
        }, null, 2);
    }

    /**
     * Import metrics from JSON
     */
    importMetrics(jsonData: string): void {
        try {
            const data = JSON.parse(jsonData);

            if (data.metrics) {
                this.metrics = new Map(data.metrics);
            }

            if (data.benchmarks) {
                this.benchmarks = new Map(data.benchmarks);
            }
        } catch (error) {
            console.error('Failed to import metrics:', error);
        }
    }

    /**
     * Update percentiles for a metric
     */
    private updatePercentiles(metric: PerformanceMetric): void {
        if (metric.durations.length === 0) return;

        const sorted = [...metric.durations].sort((a, b) => a - b);
        const p95Index = Math.floor(sorted.length * 0.95);
        const p99Index = Math.floor(sorted.length * 0.99);

        metric.p95Duration = sorted[p95Index] || 0;
        metric.p99Duration = sorted[p99Index] || 0;
    }

    /**
     * Force percentile calculation for all metrics (for final reporting)
     */
    calculateAllPercentiles(): void {
        for (const metric of this.metrics.values()) {
            this.updatePercentiles(metric);
        }
    }

    /**
     * Calculate statistics for an array of numbers
     */
    private calculateStats(values: number[]): BenchmarkStats {
        if (values.length === 0) {
            return { min: 0, max: 0, avg: 0, median: 0, p95: 0, p99: 0, stdDev: 0 };
        }

        const sorted = [...values].sort((a, b) => a - b);
        const sum = values.reduce((a, b) => a + b, 0);
        const avg = sum / values.length;

        // Calculate standard deviation
        const variance = values.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / values.length;
        const stdDev = Math.sqrt(variance);

        return {
            min: sorted[0],
            max: sorted[sorted.length - 1],
            avg,
            median: sorted[Math.floor(sorted.length / 2)],
            p95: sorted[Math.floor(sorted.length * 0.95)],
            p99: sorted[Math.floor(sorted.length * 0.99)],
            stdDev
        };
    }
}

/**
 * Performance timer utility
 */
export class PerformanceTimer {
    private startTime: number;
    private endTime?: number;

    constructor(
        private operationName: string,
        private monitor: PerformanceMonitor,
        private metadata?: Record<string, any>
    ) {
        this.startTime = performance.now();
    }

    /**
     * End timing and record the metric
     */
    end(): number {
        this.endTime = performance.now();
        const duration = this.endTime - this.startTime;
        this.monitor.recordMetric(this.operationName, duration, this.metadata);
        return duration;
    }

    /**
     * Get elapsed time without ending the timer
     */
    elapsed(): number {
        return performance.now() - this.startTime;
    }
}

/**
 * Performance metric interface
 */
export interface PerformanceMetric {
    name: string;
    count: number;
    totalDuration: number;
    minDuration: number;
    maxDuration: number;
    avgDuration: number;
    p95Duration: number;
    p99Duration: number;
    durations: number[];
    metadata: Record<string, any>;
}

/**
 * Benchmark result interface
 */
export interface BenchmarkResult {
    name: string;
    iterations: number;
    original: BenchmarkStats;
    optimized: BenchmarkStats;
    improvement: {
        avgSpeedup: number;
        medianSpeedup: number;
        p95Speedup: number;
        p99Speedup: number;
    };
    timestamp: number;
}

/**
 * Benchmark statistics interface
 */
export interface BenchmarkStats {
    min: number;
    max: number;
    avg: number;
    median: number;
    p95: number;
    p99: number;
    stdDev: number;
}

/**
 * Performance summary interface
 */
export interface PerformanceSummary {
    totalOperations: number;
    totalMetrics: number;
    avgDuration: number;
    slowestOperations: PerformanceMetric[];
    fastestOperations: PerformanceMetric[];
    benchmarks: number;
    lastUpdated: number;
}