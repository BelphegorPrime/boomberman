import { detectionErrorHandler } from './ErrorHandler.js';
import { GeoAnalyzer } from './analyzers/GeoAnalyzer.js';

/**
 * Health status levels
 */
export enum HealthStatus {
    HEALTHY = 'HEALTHY',
    DEGRADED = 'DEGRADED',
    UNHEALTHY = 'UNHEALTHY',
}

/**
 * Component health information
 */
interface ComponentHealth {
    status: HealthStatus;
    message: string;
    lastChecked: number;
    responseTime?: number;
    errorCount?: number;
    details?: Record<string, any>;
}

/**
 * Overall system health
 */
export interface SystemHealth {
    status: HealthStatus;
    timestamp: number;
    components: {
        errorHandler: ComponentHealth;
        geoAnalyzer: ComponentHealth;
        circuitBreakers: ComponentHealth;
        overall: ComponentHealth;
    };
    metrics: {
        totalErrors: number;
        errorRate: number;
        averageResponseTime: number;
    };
}

/**
 * Health monitoring for the detection system
 */
export class HealthMonitor {
    private lastHealthCheck = 0;
    private healthCheckInterval = 30000; // 30 seconds
    private cachedHealth: SystemHealth | null = null;

    /**
     * Get current system health
     */
    async getHealth(forceRefresh = false): Promise<SystemHealth> {
        const now = Date.now();

        if (!forceRefresh &&
            this.cachedHealth &&
            (now - this.lastHealthCheck) < this.healthCheckInterval) {
            return this.cachedHealth;
        }

        const health = await this.performHealthCheck();
        this.cachedHealth = health;
        this.lastHealthCheck = now;

        return health;
    }

    /**
     * Perform comprehensive health check
     */
    private async performHealthCheck(): Promise<SystemHealth> {
        const timestamp = Date.now();
        const components = {
            errorHandler: await this.checkErrorHandler(),
            geoAnalyzer: await this.checkGeoAnalyzer(),
            circuitBreakers: await this.checkCircuitBreakers(),
            overall: { status: HealthStatus.HEALTHY, message: 'All systems operational', lastChecked: timestamp }
        };

        // Determine overall status
        const componentStatuses = Object.values(components).map(c => c.status);
        let overallStatus = HealthStatus.HEALTHY;

        if (componentStatuses.includes(HealthStatus.UNHEALTHY)) {
            overallStatus = HealthStatus.UNHEALTHY;
            components.overall.status = HealthStatus.UNHEALTHY;
            components.overall.message = 'One or more components are unhealthy';
        } else if (componentStatuses.includes(HealthStatus.DEGRADED)) {
            overallStatus = HealthStatus.DEGRADED;
            components.overall.status = HealthStatus.DEGRADED;
            components.overall.message = 'System is running with degraded performance';
        }

        // Calculate metrics
        const errorStats = detectionErrorHandler.getErrorStats();
        const totalErrors = Object.values(errorStats.errorCounts).reduce((sum, count) => sum + count, 0);

        return {
            status: overallStatus,
            timestamp,
            components,
            metrics: {
                totalErrors,
                errorRate: this.calculateErrorRate(errorStats),
                averageResponseTime: 25, // This would be calculated from actual metrics
            },
        };
    }

    /**
     * Check error handler health
     */
    private async checkErrorHandler(): Promise<ComponentHealth> {
        const startTime = Date.now();

        try {
            const isHealthy = detectionErrorHandler.isHealthy();
            const errorStats = detectionErrorHandler.getErrorStats();
            const responseTime = Date.now() - startTime;

            if (!isHealthy) {
                return {
                    status: HealthStatus.DEGRADED,
                    message: 'Error handler reports degraded performance',
                    lastChecked: Date.now(),
                    responseTime,
                    details: errorStats,
                };
            }

            const totalErrors = Object.values(errorStats.errorCounts).reduce((sum, count) => sum + count, 0);

            return {
                status: HealthStatus.HEALTHY,
                message: 'Error handler is functioning normally',
                lastChecked: Date.now(),
                responseTime,
                errorCount: totalErrors,
                details: {
                    circuitBreakerStates: errorStats.circuitBreakerStates,
                },
            };
        } catch (error) {
            return {
                status: HealthStatus.UNHEALTHY,
                message: `Error handler check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                lastChecked: Date.now(),
                responseTime: Date.now() - startTime,
            };
        }
    }

    /**
     * Check GeoAnalyzer health
     */
    private async checkGeoAnalyzer(): Promise<ComponentHealth> {
        const startTime = Date.now();

        try {
            // Create a test GeoAnalyzer instance
            const geoAnalyzer = new GeoAnalyzer();

            if (!geoAnalyzer.isInitialized()) {
                return {
                    status: HealthStatus.DEGRADED,
                    message: 'GeoAnalyzer not initialized - running in simulation mode',
                    lastChecked: Date.now(),
                    responseTime: Date.now() - startTime,
                    details: {
                        usingRealDatabases: false,
                    },
                };
            }

            // Test with a known IP
            const testResult = await geoAnalyzer.analyze('8.8.8.8');
            const responseTime = Date.now() - startTime;

            if (testResult.country === 'unknown') {
                return {
                    status: HealthStatus.DEGRADED,
                    message: 'GeoAnalyzer returning unknown results - may be using simulation',
                    lastChecked: Date.now(),
                    responseTime,
                    details: {
                        testResult,
                        usingRealDatabases: geoAnalyzer.isUsingRealDatabases(),
                    },
                };
            }

            return {
                status: HealthStatus.HEALTHY,
                message: 'GeoAnalyzer is functioning normally',
                lastChecked: Date.now(),
                responseTime,
                details: {
                    usingRealDatabases: geoAnalyzer.isUsingRealDatabases(),
                    testResult: {
                        country: testResult.country,
                        organization: testResult.organization,
                    },
                },
            };
        } catch (error) {
            return {
                status: HealthStatus.UNHEALTHY,
                message: `GeoAnalyzer check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                lastChecked: Date.now(),
                responseTime: Date.now() - startTime,
            };
        }
    }

    /**
     * Check circuit breaker health
     */
    private async checkCircuitBreakers(): Promise<ComponentHealth> {
        const startTime = Date.now();

        try {
            const errorStats = detectionErrorHandler.getErrorStats();
            const geoCircuitBreaker = detectionErrorHandler.getGeoCircuitBreaker();
            const geoStats = geoCircuitBreaker.getStats();

            let status = HealthStatus.HEALTHY;
            let message = 'All circuit breakers are closed';

            if (geoStats.state === 'OPEN') {
                status = HealthStatus.DEGRADED;
                message = 'Geo service circuit breaker is open';
            } else if (geoStats.state === 'HALF_OPEN') {
                status = HealthStatus.DEGRADED;
                message = 'Geo service circuit breaker is half-open (testing)';
            }

            return {
                status,
                message,
                lastChecked: Date.now(),
                responseTime: Date.now() - startTime,
                details: {
                    geoCircuitBreaker: geoStats,
                },
            };
        } catch (error) {
            return {
                status: HealthStatus.UNHEALTHY,
                message: `Circuit breaker check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                lastChecked: Date.now(),
                responseTime: Date.now() - startTime,
            };
        }
    }

    /**
     * Calculate error rate from error statistics
     */
    private calculateErrorRate(errorStats: ReturnType<typeof detectionErrorHandler.getErrorStats>): number {
        const now = Date.now();
        const oneHourAgo = now - (60 * 60 * 1000);

        // Count recent errors (within last hour)
        let recentErrors = 0;
        for (const [errorType, timestamp] of Object.entries(errorStats.lastErrors)) {
            if (timestamp > oneHourAgo) {
                recentErrors += errorStats.errorCounts[errorType] || 0;
            }
        }

        // This is a simplified calculation - in a real system you'd track requests per hour
        const estimatedRequestsPerHour = 1000; // This should come from actual metrics
        return recentErrors / estimatedRequestsPerHour;
    }

    /**
     * Reset health check cache
     */
    resetCache(): void {
        this.cachedHealth = null;
        this.lastHealthCheck = 0;
    }

    /**
     * Set health check interval
     */
    setHealthCheckInterval(intervalMs: number): void {
        this.healthCheckInterval = intervalMs;
    }
}

// Export singleton instance
export const healthMonitor = new HealthMonitor();