import { describe, test, expect, beforeEach, jest } from '@jest/globals';
import { Request } from 'express';
import {
    DetectionErrorHandler,
    CircuitBreaker,
    PerformanceGuard,
    DetectionErrorType,
    CircuitBreakerState,
} from '../src/detection/ErrorHandler.js';

// Mock request object
const createMockRequest = (headers: Record<string, string> = {}): Partial<Request> => ({
    headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.5',
        'accept-encoding': 'gzip, deflate',
        ...headers,
    },
    path: '/test',
    method: 'GET',
});

describe('CircuitBreaker', () => {
    let circuitBreaker: CircuitBreaker;

    beforeEach(() => {
        circuitBreaker = new CircuitBreaker({
            failureThreshold: 3,
            recoveryTimeout: 1000,
            minimumRequests: 2,
        });
    });

    test('should start in CLOSED state', () => {
        expect(circuitBreaker.getState()).toBe(CircuitBreakerState.CLOSED);
    });

    test('should execute operation successfully when closed', async () => {
        const operation = jest.fn().mockResolvedValue('success');
        const fallback = 'fallback';

        const result = await circuitBreaker.execute(operation, fallback);

        expect(result).toBe('success');
        expect(operation).toHaveBeenCalled();
    });

    test('should return fallback when operation fails', async () => {
        const operation = jest.fn().mockRejectedValue(new Error('Operation failed'));
        const fallback = 'fallback';

        const result = await circuitBreaker.execute(operation, fallback);

        expect(result).toBe('fallback');
        expect(operation).toHaveBeenCalled();
    });

    test('should open circuit after failure threshold', async () => {
        const operation = jest.fn().mockRejectedValue(new Error('Operation failed'));
        const fallback = 'fallback';

        // Execute enough requests to meet minimum threshold
        await circuitBreaker.execute(operation, fallback);
        await circuitBreaker.execute(operation, fallback);

        // Now exceed failure threshold
        await circuitBreaker.execute(operation, fallback);

        expect(circuitBreaker.getState()).toBe(CircuitBreakerState.OPEN);
    });

    test('should return fallback immediately when circuit is open', async () => {
        const operation = jest.fn().mockRejectedValue(new Error('Operation failed'));
        const fallback = 'fallback';

        // Open the circuit
        await circuitBreaker.execute(operation, fallback);
        await circuitBreaker.execute(operation, fallback);
        await circuitBreaker.execute(operation, fallback);

        expect(circuitBreaker.getState()).toBe(CircuitBreakerState.OPEN);

        // Reset mock to track calls
        operation.mockClear();

        // Execute again - should not call operation
        const result = await circuitBreaker.execute(operation, fallback);

        expect(result).toBe('fallback');
        expect(operation).not.toHaveBeenCalled();
    });

    test('should transition to HALF_OPEN after recovery timeout', async () => {
        const operation = jest.fn().mockRejectedValue(new Error('Operation failed'));
        const fallback = 'fallback';

        // Open the circuit
        await circuitBreaker.execute(operation, fallback);
        await circuitBreaker.execute(operation, fallback);
        await circuitBreaker.execute(operation, fallback);

        expect(circuitBreaker.getState()).toBe(CircuitBreakerState.OPEN);

        // Wait for recovery timeout (simulate by manipulating time)
        jest.useFakeTimers();
        jest.advanceTimersByTime(1100); // Slightly more than recovery timeout

        // Next execution should attempt to call operation (HALF_OPEN)
        operation.mockResolvedValueOnce('success');
        const result = await circuitBreaker.execute(operation, fallback);

        expect(result).toBe('success');
        expect(circuitBreaker.getState()).toBe(CircuitBreakerState.CLOSED);

        jest.useRealTimers();
    });

    test('should reset statistics', () => {
        const stats = circuitBreaker.getStats();
        expect(stats.failureCount).toBe(0);
        expect(stats.requestCount).toBe(0);

        circuitBreaker.reset();

        const resetStats = circuitBreaker.getStats();
        expect(resetStats.state).toBe(CircuitBreakerState.CLOSED);
        expect(resetStats.failureCount).toBe(0);
        expect(resetStats.requestCount).toBe(0);
    });
});

describe('PerformanceGuard', () => {
    let performanceGuard: PerformanceGuard;

    beforeEach(() => {
        performanceGuard = new PerformanceGuard(100); // 100ms timeout
    });

    test('should execute operation successfully within timeout', async () => {
        const operation = jest.fn().mockResolvedValue('success');
        const fallback = 'fallback';

        const result = await performanceGuard.executeWithTimeout(operation, fallback);

        expect(result).toBe('success');
        expect(operation).toHaveBeenCalled();
    });

    test('should return fallback on timeout', async () => {
        const operation = jest.fn().mockImplementation(() =>
            new Promise(resolve => setTimeout(() => resolve('success'), 200))
        );
        const fallback = 'fallback';

        const result = await performanceGuard.executeWithTimeout(operation, fallback, 50);

        expect(result).toBe('fallback');
    });

    test('should propagate non-timeout errors', async () => {
        const operation = jest.fn().mockRejectedValue(new Error('Not a timeout'));
        const fallback = 'fallback';

        await expect(performanceGuard.executeWithTimeout(operation, fallback))
            .rejects.toThrow('Not a timeout');
    });
});

describe('DetectionErrorHandler', () => {
    let errorHandler: DetectionErrorHandler;

    beforeEach(() => {
        errorHandler = new DetectionErrorHandler();
        errorHandler.resetErrorStats();
    });

    test('should handle geo service failure', async () => {
        const result = await errorHandler.handleGeoServiceFailure('8.8.8.8');

        expect(result).toEqual({
            country: 'unknown',
            region: 'unknown',
            city: 'unknown',
            isVPN: false,
            isProxy: false,
            isHosting: false,
            isTor: false,
            riskScore: 10,
            asn: 0,
            organization: 'unknown',
        });
    });

    test('should handle geo service failure for private IP', async () => {
        const result = await errorHandler.handleGeoServiceFailure('192.168.1.1');

        expect(result).toEqual({
            country: 'local',
            region: 'local',
            city: 'local',
            isVPN: false,
            isProxy: false,
            isHosting: false,
            isTor: false,
            riskScore: 0,
            asn: 0,
            organization: 'local',
        });
    });

    test('should handle HTTP fingerprinting error', () => {
        const req = createMockRequest() as Request;
        const error = new Error('Fingerprinting failed');

        const result = errorHandler.handleFingerprintingError(req, error);

        expect(result).toMatchObject({
            headerSignature: expect.any(String),
            missingHeaders: expect.any(Array),
            suspiciousHeaders: expect.any(Array),
            headerOrderScore: expect.any(Number),
            automationSignatures: expect.any(Array),
        });
    });

    test('should detect automation signatures in basic fingerprint', () => {
        const req = createMockRequest({
            'user-agent': 'Mozilla/5.0 (compatible; selenium)',
        }) as Request;
        const error = new Error('Fingerprinting failed');

        const result = errorHandler.handleFingerprintingError(req, error);

        expect(result.automationSignatures).toContain('selenium');
    });

    test('should handle behavior analysis error', () => {
        const error = new Error('Behavior analysis failed');

        const result = errorHandler.handleBehaviorAnalysisError('192.168.1.1', error);

        expect(result).toEqual({
            requestInterval: 2000,
            navigationPattern: [],
            timingConsistency: 0.5,
            humanLikeScore: 0.5,
            sessionDuration: 0,
        });
    });

    test('should handle TLS analysis error', () => {
        const error = new Error('TLS analysis failed');

        const result = errorHandler.handleTLSAnalysisError(error);

        expect(result).toBeUndefined();
    });

    test('should handle scoring engine error', () => {
        const req = createMockRequest() as Request;
        const error = new Error('Scoring engine failed');

        const result = errorHandler.handleScoringEngineError(req, '192.168.1.1', error);

        expect(result).toMatchObject({
            isSuspicious: expect.any(Boolean),
            suspicionScore: expect.any(Number),
            confidence: 0.3,
            reasons: expect.any(Array),
            fingerprint: expect.stringMatching(/^fallback-/),
            metadata: expect.objectContaining({
                fallbackReason: 'Scoring engine failure',
            }),
        });
    });

    test('should handle timeout error', () => {
        const req = createMockRequest() as Request;

        const result = errorHandler.handleTimeoutError(req, '192.168.1.1');

        expect(result).toMatchObject({
            isSuspicious: expect.any(Boolean),
            suspicionScore: expect.any(Number),
            confidence: 0.2,
            reasons: expect.arrayContaining([
                expect.objectContaining({
                    description: 'Analysis timed out - using basic fallback detection',
                }),
            ]),
            metadata: expect.objectContaining({
                fallbackReason: 'Analysis timeout',
                timeoutOccurred: true,
            }),
        });
    });

    test('should execute operation with error handling', async () => {
        const operation = jest.fn().mockResolvedValue('success');
        const fallback = 'fallback';

        const result = await errorHandler.executeWithErrorHandling(
            operation,
            fallback,
            DetectionErrorType.HTTP_FINGERPRINT_ERROR
        );

        expect(result).toBe('success');
        expect(operation).toHaveBeenCalled();
    });

    test('should return fallback on operation error', async () => {
        const operation = jest.fn().mockRejectedValue(new Error('Operation failed'));
        const fallback = 'fallback';

        const result = await errorHandler.executeWithErrorHandling(
            operation,
            fallback,
            DetectionErrorType.HTTP_FINGERPRINT_ERROR
        );

        expect(result).toBe('fallback');
    });

    test('should track error statistics', async () => {
        const operation = jest.fn().mockRejectedValue(new Error('Operation failed'));
        const fallback = 'fallback';

        await errorHandler.executeWithErrorHandling(
            operation,
            fallback,
            DetectionErrorType.HTTP_FINGERPRINT_ERROR
        );

        const stats = errorHandler.getErrorStats();
        expect(stats.errorCounts[DetectionErrorType.HTTP_FINGERPRINT_ERROR]).toBe(1);
        expect(stats.lastErrors[DetectionErrorType.HTTP_FINGERPRINT_ERROR]).toBeGreaterThan(0);
    });

    test('should report healthy status initially', () => {
        expect(errorHandler.isHealthy()).toBe(true);
    });

    test('should reset error statistics', () => {
        // Generate some errors first
        errorHandler.handleTLSAnalysisError(new Error('Test error'));

        let stats = errorHandler.getErrorStats();
        expect(Object.keys(stats.errorCounts)).toHaveLength(1);

        errorHandler.resetErrorStats();

        stats = errorHandler.getErrorStats();
        expect(Object.keys(stats.errorCounts)).toHaveLength(0);
    });

    test('should provide circuit breaker access', () => {
        const circuitBreaker = errorHandler.getGeoCircuitBreaker();
        expect(circuitBreaker).toBeInstanceOf(CircuitBreaker);
        expect(circuitBreaker.getState()).toBe(CircuitBreakerState.CLOSED);
    });
});

describe('Error Handler Integration', () => {
    let errorHandler: DetectionErrorHandler;

    beforeEach(() => {
        errorHandler = new DetectionErrorHandler();
        errorHandler.resetErrorStats();
    });

    test('should handle cascading failures gracefully', async () => {
        const req = createMockRequest() as Request;
        const ip = '8.8.8.8';

        // Simulate multiple component failures
        const geoResult = await errorHandler.handleGeoServiceFailure(ip);
        const fingerprintResult = errorHandler.handleFingerprintingError(req, new Error('Fingerprint failed'));
        const behaviorResult = errorHandler.handleBehaviorAnalysisError(ip, new Error('Behavior failed'));
        const scoringResult = errorHandler.handleScoringEngineError(req, ip, new Error('Scoring failed'));

        // All should return valid fallback data
        expect(geoResult.country).toBeDefined();
        expect(fingerprintResult.headerSignature).toBeDefined();
        expect(behaviorResult.humanLikeScore).toBeDefined();
        expect(scoringResult.suspicionScore).toBeDefined();

        // Error statistics should be tracked
        const stats = errorHandler.getErrorStats();
        expect(Object.keys(stats.errorCounts).length).toBeGreaterThan(0);
    });

    test('should maintain system stability under high error rates', async () => {
        const req = createMockRequest() as Request;
        const ip = '8.8.8.8';

        // Generate many errors
        for (let i = 0; i < 50; i++) {
            await errorHandler.handleGeoServiceFailure(ip);
            errorHandler.handleFingerprintingError(req, new Error(`Error ${i}`));
        }

        // System should still be responsive
        const result = errorHandler.handleTimeoutError(req, ip);
        expect(result.suspicionScore).toBeGreaterThanOrEqual(0);
        expect(result.suspicionScore).toBeLessThanOrEqual(100);

        // Error stats should be available
        const stats = errorHandler.getErrorStats();
        expect(stats.errorCounts[DetectionErrorType.GEO_SERVICE_FAILURE]).toBe(50);
        expect(stats.errorCounts[DetectionErrorType.HTTP_FINGERPRINT_ERROR]).toBe(50);
    });
});