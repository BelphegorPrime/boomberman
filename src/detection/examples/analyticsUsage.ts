/**
 * Example usage of the Analytics Service
 * This file demonstrates how to use the analytics and reporting capabilities
 */

import { getAnalyticsService, type AnalyticsReportConfig } from '../AnalyticsService.js';
import { getMetricsCollector } from '../../utils/logger/metricsCollector.js';
import type { DetectionResult } from '../types/DetectionResult.js';
import type { PerformanceMetrics } from '../../utils/logger/detectionLogger.js';

/**
 * Example: Generate a comprehensive analytics report
 */
export async function generateDailyReport(): Promise<void> {
    const analyticsService = getAnalyticsService();

    const config: AnalyticsReportConfig = {
        timeRange: 'day',
        includeGeoDistribution: true,
        includeThreatSummary: true,
        includePerformanceMetrics: true,
        maxThreats: 20,
        maxCountries: 15,
    };

    try {
        const report = await analyticsService.generateReport(config);

        console.log('=== Daily Analytics Report ===');
        console.log(`Generated at: ${new Date(report.metadata.generatedAt).toISOString()}`);
        console.log(`Time range: ${report.metadata.timeRange}`);
        console.log('\n--- Summary ---');
        console.log(`Total requests: ${report.summary.totalRequests}`);
        console.log(`Suspicious requests: ${report.summary.suspiciousRequests}`);
        console.log(`Blocked requests: ${report.summary.blockedRequests}`);
        console.log(`Detection accuracy: ${(report.summary.detectionAccuracy * 100).toFixed(2)}%`);
        console.log(`False positive rate: ${(report.summary.falsePositiveRate * 100).toFixed(2)}%`);
        console.log(`Average processing time: ${report.summary.averageProcessingTime.toFixed(2)}ms`);

        console.log('\n--- Top Threats ---');
        report.threats.slice(0, 5).forEach((threat, index) => {
            console.log(`${index + 1}. ${threat.ip} (${threat.country})`);
            console.log(`   Score: ${threat.averageScore.toFixed(1)}, Requests: ${threat.totalRequests}`);
            console.log(`   Types: ${threat.threatTypes.join(', ')}`);
        });

        console.log('\n--- Geographic Distribution ---');
        report.geoDistribution.byCountry.slice(0, 5).forEach((country, index) => {
            console.log(`${index + 1}. ${country.country}: ${country.requests} requests (${country.percentage.toFixed(1)}%)`);
        });

        console.log('\n--- Performance Metrics ---');
        console.log(`P50 response time: ${report.performanceMetrics.responseTimePercentiles.p50.toFixed(2)}ms`);
        console.log(`P95 response time: ${report.performanceMetrics.responseTimePercentiles.p95.toFixed(2)}ms`);
        console.log(`Requests per second: ${report.performanceMetrics.throughputMetrics.requestsPerSecond.toFixed(2)}`);
        console.log(`Cache hit rate: ${(report.performanceMetrics.resourceUtilization.cacheHitRate * 100).toFixed(2)}%`);

    } catch (error) {
        console.error('Failed to generate analytics report:', error);
    }
}

/**
 * Example: Monitor real-time dashboard
 */
export function monitorRealTimeDashboard(): void {
    const analyticsService = getAnalyticsService();

    // Set up real-time monitoring
    const interval = setInterval(() => {
        const dashboard = analyticsService.getRealTimeDashboard();

        console.log('\n=== Real-Time Dashboard ===');
        console.log(`Requests/sec: ${dashboard.realTimeMetrics.requestsPerSecond.toFixed(2)}`);
        console.log(`Avg response time: ${dashboard.realTimeMetrics.averageResponseTime.toFixed(2)}ms`);
        console.log(`Suspicious rate: ${(dashboard.realTimeMetrics.suspiciousRequestRate * 100).toFixed(2)}%`);
        console.log(`Error rate: ${(dashboard.realTimeMetrics.errorRate * 100).toFixed(2)}%`);
        console.log(`Active alerts: ${dashboard.alertsCount}`);

        if (dashboard.recentThreats.length > 0) {
            console.log('\n--- Recent Threats ---');
            dashboard.recentThreats.forEach((threat, index) => {
                console.log(`${index + 1}. ${threat.ip}: ${threat.averageScore.toFixed(1)} (${threat.country})`);
            });
        }

        // Stop monitoring after 5 iterations (for example purposes)
        if (Math.random() > 0.8) {
            clearInterval(interval);
            console.log('\nReal-time monitoring stopped.');
        }
    }, 10000); // Update every 10 seconds
}

/**
 * Example: Generate threat intelligence report
 */
export function generateThreatIntelligence(): void {
    const analyticsService = getAnalyticsService();

    const intelligence = analyticsService.generateThreatIntelligence();

    console.log('\n=== Threat Intelligence Report ===');

    console.log('\n--- Emerging Threats ---');
    intelligence.emergingThreats.slice(0, 5).forEach((threat, index) => {
        console.log(`${index + 1}. ${threat.ip} (${threat.country})`);
        console.log(`   Score: ${threat.averageScore.toFixed(1)}, Last seen: ${new Date(threat.lastSeen).toLocaleString()}`);
    });

    console.log('\n--- Repeat Offenders ---');
    intelligence.repeatOffenders.slice(0, 5).forEach((threat, index) => {
        console.log(`${index + 1}. ${threat.ip} (${threat.country})`);
        console.log(`   Requests: ${threat.totalRequests}, Avg score: ${threat.averageScore.toFixed(1)}`);
    });

    console.log('\n--- Geographic Hotspots ---');
    intelligence.geographicHotspots.slice(0, 5).forEach((hotspot, index) => {
        console.log(`${index + 1}. ${hotspot.country}: Risk ${hotspot.riskScore.toFixed(1)}, Requests: ${hotspot.requestCount}`);
    });

    console.log('\n--- Attack Patterns ---');
    intelligence.attackPatterns.slice(0, 5).forEach((pattern, index) => {
        console.log(`${index + 1}. ${pattern.pattern}: ${pattern.frequency} occurrences (${pattern.severity} severity)`);
    });
}

/**
 * Example: Analyze specific IP address
 */
export function analyzeSpecificIP(ip: string): void {
    const analyticsService = getAnalyticsService();

    const ipAnalytics = analyticsService.getIPAnalytics(ip);

    console.log(`\n=== IP Analysis: ${ip} ===`);

    if (ipAnalytics.threat) {
        console.log('\n--- Threat Profile ---');
        console.log(`Country: ${ipAnalytics.threat.country}`);
        console.log(`Total requests: ${ipAnalytics.threat.totalRequests}`);
        console.log(`Average score: ${ipAnalytics.threat.averageScore.toFixed(1)}`);
        console.log(`Threat types: ${ipAnalytics.threat.threatTypes.join(', ')}`);
        console.log(`Last seen: ${new Date(ipAnalytics.threat.lastSeen).toLocaleString()}`);
    } else {
        console.log('No threat data available for this IP.');
    }

    console.log('\n--- Risk Assessment ---');
    console.log(`Risk level: ${ipAnalytics.riskAssessment.riskLevel.toUpperCase()}`);
    console.log('Risk factors:');
    ipAnalytics.riskAssessment.riskFactors.forEach((factor, index) => {
        console.log(`  ${index + 1}. ${factor}`);
    });
    console.log('Recommendations:');
    ipAnalytics.riskAssessment.recommendations.forEach((rec, index) => {
        console.log(`  ${index + 1}. ${rec}`);
    });

    if (ipAnalytics.historicalActivity.length > 0) {
        console.log('\n--- Historical Activity ---');
        ipAnalytics.historicalActivity.slice(0, 10).forEach((activity, index) => {
            console.log(`${index + 1}. ${new Date(activity.timestamp).toLocaleString()}: Score ${activity.suspicionScore}, Action: ${activity.action}`);
        });
    }
}

/**
 * Example: Export analytics data
 */
export async function exportAnalyticsData(): Promise<void> {
    const analyticsService = getAnalyticsService();

    const config: AnalyticsReportConfig = {
        timeRange: 'week',
        includeGeoDistribution: true,
        includeThreatSummary: true,
        includePerformanceMetrics: false,
        maxThreats: 50,
        maxCountries: 20,
    };

    try {
        // Export as JSON
        const jsonData = analyticsService.exportData('json', config);
        console.log('\n=== JSON Export Sample ===');
        const parsed = JSON.parse(jsonData);
        console.log(`Total requests: ${parsed.totalRequests}`);
        console.log(`Top threats: ${parsed.topThreats.length}`);

        // Export as CSV
        const csvData = analyticsService.exportData('csv', config);
        console.log('\n=== CSV Export Sample ===');
        const lines = csvData.split('\n');
        console.log('Headers:', lines[0]);
        if (lines.length > 1) {
            console.log('First row:', lines[1]);
        }

    } catch (error) {
        console.error('Failed to export analytics data:', error);
    }
}

/**
 * Example: Set up event listeners for real-time analytics
 */
export function setupAnalyticsEventListeners(): void {
    const analyticsService = getAnalyticsService();

    // Listen for detection events
    analyticsService.on('detectionEvent', (event) => {
        if (event.result.suspicionScore > 70) {
            console.log(`🚨 High-risk detection: ${event.ip} (score: ${event.result.suspicionScore})`);
        }
    });

    // Listen for error events
    analyticsService.on('errorEvent', (event) => {
        console.log(`❌ Detection error in ${event.component}: ${event.error.message}`);
    });

    // Listen for metrics updates
    analyticsService.on('metricsUpdate', (metrics) => {
        if (metrics.errorRate > 0.05) { // 5% error rate threshold
            console.log(`⚠️  High error rate detected: ${(metrics.errorRate * 100).toFixed(2)}%`);
        }
    });

    // Listen for report generation
    analyticsService.on('reportGenerated', (event) => {
        console.log(`📊 Analytics report generated for ${event.config.timeRange} range`);
    });

    console.log('Analytics event listeners set up successfully.');
}

/**
 * Example: Simulate some detection data for demonstration
 */
export function simulateDetectionData(): void {
    const metricsCollector = getMetricsCollector();

    // Simulate legitimate traffic
    for (let i = 0; i < 10; i++) {
        const result: DetectionResult = {
            isSuspicious: false,
            suspicionScore: Math.random() * 30,
            confidence: 0.8 + Math.random() * 0.2,
            reasons: [],
            fingerprint: `legitimate-${i}`,
            metadata: {
                timestamp: Date.now() - Math.random() * 3600000, // Random time in last hour
                processingTime: 15 + Math.random() * 20,
                detectorVersions: { example: '1.0.0' },
                geoData: {
                    country: ['US', 'CA', 'GB', 'DE', 'FR'][Math.floor(Math.random() * 5)],
                    region: 'Test Region',
                    city: 'Test City',
                    isVPN: false,
                    isProxy: false,
                    isHosting: false,
                    isTor: false,
                    riskScore: Math.random() * 20,
                    asn: 12345,
                    organization: 'Test ISP',
                },
            },
        };

        const metrics: PerformanceMetrics = {
            totalProcessingTime: result.metadata.processingTime,
            fingerprintingTime: result.metadata.processingTime * 0.2,
            behaviorAnalysisTime: result.metadata.processingTime * 0.3,
            geoAnalysisTime: result.metadata.processingTime * 0.3,
            scoringTime: result.metadata.processingTime * 0.2,
            memoryUsage: process.memoryUsage(),
        };

        metricsCollector.recordDetection(`192.168.1.${i}`, result, metrics, false);
    }

    // Simulate suspicious traffic
    for (let i = 0; i < 5; i++) {
        const result: DetectionResult = {
            isSuspicious: true,
            suspicionScore: 50 + Math.random() * 50,
            confidence: 0.7 + Math.random() * 0.3,
            reasons: [
                {
                    category: ['fingerprint', 'behavioral', 'geographic'][Math.floor(Math.random() * 3)] as any,
                    severity: 'high' as const,
                    description: 'Suspicious activity detected',
                    score: 50 + Math.random() * 50,
                },
            ],
            fingerprint: `suspicious-${i}`,
            metadata: {
                timestamp: Date.now() - Math.random() * 3600000,
                processingTime: 25 + Math.random() * 30,
                detectorVersions: { example: '1.0.0' },
                geoData: {
                    country: ['CN', 'RU', 'KP', 'IR', 'BR'][Math.floor(Math.random() * 5)],
                    region: 'Test Region',
                    city: 'Test City',
                    isVPN: Math.random() > 0.5,
                    isProxy: Math.random() > 0.7,
                    isHosting: Math.random() > 0.6,
                    isTor: Math.random() > 0.9,
                    riskScore: 40 + Math.random() * 60,
                    asn: 54321,
                    organization: 'Suspicious ISP',
                },
            },
        };

        const metrics: PerformanceMetrics = {
            totalProcessingTime: result.metadata.processingTime,
            fingerprintingTime: result.metadata.processingTime * 0.25,
            behaviorAnalysisTime: result.metadata.processingTime * 0.35,
            geoAnalysisTime: result.metadata.processingTime * 0.25,
            scoringTime: result.metadata.processingTime * 0.15,
            memoryUsage: process.memoryUsage(),
        };

        metricsCollector.recordDetection(`10.0.0.${i}`, result, metrics, Math.random() > 0.5);
    }

    console.log('Simulated detection data generated successfully.');
}

/**
 * Main demonstration function
 */
export async function demonstrateAnalytics(): Promise<void> {
    console.log('🔍 Enhanced Bot Detection Analytics Demo\n');

    // Simulate some data first
    simulateDetectionData();

    // Set up event listeners
    setupAnalyticsEventListeners();

    // Wait a moment for data to be processed
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Generate reports
    await generateDailyReport();
    generateThreatIntelligence();

    // Analyze specific IPs
    analyzeSpecificIP('10.0.0.1');
    analyzeSpecificIP('192.168.1.5');

    // Export data
    await exportAnalyticsData();

    console.log('\n✅ Analytics demonstration completed!');
}

// Run demonstration if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    demonstrateAnalytics().catch(console.error);
}