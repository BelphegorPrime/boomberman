// Export all types and analyzers
export * from './types/index.js';
export * from './analyzers/index.js';

// Export cache and performance components
export * from './cache/index.js';
export * from './performance/index.js';

// Export threat scoring engine
export { ThreatScoringEngine } from './ThreatScoringEngine.js';

// Export configuration manager
export {
    ConfigurationManager,
    ConfigurationError,
    getConfigurationManager,
    initializeConfigurationManager
} from './ConfigurationManager.js';

// Export whitelist manager
export {
    WhitelistManager,
    getWhitelistManager,
    initializeWhitelistManager,
    type WhitelistEntry,
    type WhitelistConfig,
    type WhitelistResult
} from './WhitelistManager.js';

// Export optimized analyzers
export { OptimizedBehaviorAnalyzer } from './analyzers/OptimizedBehaviorAnalyzer.js';
export { OptimizedGeoAnalyzer } from './analyzers/OptimizedGeoAnalyzer.js';
export { OptimizedHTTPFingerprintAnalyzer } from './analyzers/OptimizedHTTPFingerprintAnalyzer.js';

// Export analytics service
export {
    AnalyticsService,
    getAnalyticsService,
    type AnalyticsReport,
    type AnalyticsReportConfig,
    type GeographicDistribution,
    type PerformanceReport,
    type TrendAnalysis,
    type ThreatIntelligence,
    type TimeRange
} from './AnalyticsService.js';