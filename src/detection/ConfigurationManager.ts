import { EventEmitter } from 'events';
import { DetectionConfig, DEFAULT_DETECTION_CONFIG } from './types/Configuration.js';

/**
 * Configuration validation error
 */
export class ConfigurationError extends Error {
    constructor(message: string, public field?: string) {
        super(message);
        this.name = 'ConfigurationError';
    }
}

/**
 * Configuration manager for the enhanced bot detection system
 * Handles environment variable loading, validation, and hot-reloading
 */
export class ConfigurationManager extends EventEmitter {
    private config: DetectionConfig;
    private configPath?: string;
    private watchInterval?: NodeJS.Timeout;

    constructor(configPath?: string) {
        super();
        this.configPath = configPath;
        this.config = this.loadConfiguration();
    }

    /**
     * Get the current configuration
     */
    getConfig(): DetectionConfig {
        return { ...this.config };
    }

    /**
     * Update configuration and emit change event
     */
    updateConfig(newConfig: Partial<DetectionConfig>): void {
        const mergedConfig = this.mergeConfig(this.config, newConfig);
        this.validateConfiguration(mergedConfig);

        const oldConfig = this.config;
        this.config = mergedConfig;

        console.info('Configuration updated', {
            changes: this.getConfigChanges(oldConfig, mergedConfig),
        });

        this.emit('configChanged', this.config, oldConfig);
    }

    /**
     * Start watching for configuration changes (hot-reloading)
     */
    startWatching(intervalMs: number = 5000): void {
        if (this.watchInterval) {
            this.stopWatching();
        }

        this.watchInterval = setInterval(() => {
            try {
                const newConfig = this.loadConfiguration();
                if (this.hasConfigChanged(this.config, newConfig)) {
                    this.updateConfig(newConfig);
                }
            } catch (error) {
                console.error('Error reloading configuration', { error });
            }
        }, intervalMs);

        console.info('Configuration hot-reloading started', { intervalMs });
    }

    /**
     * Stop watching for configuration changes
     */
    stopWatching(): void {
        if (this.watchInterval) {
            clearInterval(this.watchInterval);
            this.watchInterval = undefined;
            console.info('Configuration hot-reloading stopped');
        }
    }

    /**
     * Load configuration from environment variables and defaults
     */
    private loadConfiguration(): DetectionConfig {
        const config = { ...DEFAULT_DETECTION_CONFIG };

        // Load from environment variables
        this.loadFromEnvironment(config);

        // Validate the configuration
        this.validateConfiguration(config);

        return config;
    }

    /**
     * Load configuration values from environment variables
     */
    private loadFromEnvironment(config: DetectionConfig): void {
        // Main settings
        if (process.env.BOT_DETECTION_ENABLED !== undefined) {
            config.enabled = process.env.BOT_DETECTION_ENABLED === 'true';
        }

        // Scoring weights
        if (process.env.BOT_DETECTION_WEIGHT_FINGERPRINT !== undefined) {
            config.scoringWeights.fingerprint = parseFloat(process.env.BOT_DETECTION_WEIGHT_FINGERPRINT);
        }
        if (process.env.BOT_DETECTION_WEIGHT_BEHAVIORAL !== undefined) {
            config.scoringWeights.behavioral = parseFloat(process.env.BOT_DETECTION_WEIGHT_BEHAVIORAL);
        }
        if (process.env.BOT_DETECTION_WEIGHT_GEOGRAPHIC !== undefined) {
            config.scoringWeights.geographic = parseFloat(process.env.BOT_DETECTION_WEIGHT_GEOGRAPHIC);
        }
        if (process.env.BOT_DETECTION_WEIGHT_REPUTATION !== undefined) {
            config.scoringWeights.reputation = parseFloat(process.env.BOT_DETECTION_WEIGHT_REPUTATION);
        }

        // Thresholds
        if (process.env.BOT_DETECTION_THRESHOLD_SUSPICIOUS !== undefined) {
            config.thresholds.suspicious = parseInt(process.env.BOT_DETECTION_THRESHOLD_SUSPICIOUS, 10);
        }
        if (process.env.BOT_DETECTION_THRESHOLD_HIGH_RISK !== undefined) {
            config.thresholds.highRisk = parseInt(process.env.BOT_DETECTION_THRESHOLD_HIGH_RISK, 10);
        }

        // Behavioral settings
        if (process.env.BOT_DETECTION_MIN_HUMAN_INTERVAL !== undefined) {
            config.behavioral.minHumanInterval = parseInt(process.env.BOT_DETECTION_MIN_HUMAN_INTERVAL, 10);
        }
        if (process.env.BOT_DETECTION_MAX_CONSISTENCY !== undefined) {
            config.behavioral.maxConsistency = parseFloat(process.env.BOT_DETECTION_MAX_CONSISTENCY);
        }
        if (process.env.BOT_DETECTION_SESSION_TIMEOUT !== undefined) {
            config.behavioral.sessionTimeout = parseInt(process.env.BOT_DETECTION_SESSION_TIMEOUT, 10);
        }

        // Geographic settings
        if (process.env.BOT_DETECTION_HIGH_RISK_COUNTRIES !== undefined) {
            config.geographic.highRiskCountries = process.env.BOT_DETECTION_HIGH_RISK_COUNTRIES.split(',').map(c => c.trim());
        }
        if (process.env.BOT_DETECTION_VPN_PENALTY !== undefined) {
            config.geographic.vpnPenalty = parseInt(process.env.BOT_DETECTION_VPN_PENALTY, 10);
        }
        if (process.env.BOT_DETECTION_HOSTING_PENALTY !== undefined) {
            config.geographic.hostingPenalty = parseInt(process.env.BOT_DETECTION_HOSTING_PENALTY, 10);
        }

        // Whitelist settings
        if (process.env.BOT_DETECTION_WHITELIST_IPS !== undefined) {
            config.whitelist.ips = process.env.BOT_DETECTION_WHITELIST_IPS.split(',').map(ip => ip.trim());
        }
        if (process.env.BOT_DETECTION_WHITELIST_ASNS !== undefined) {
            config.whitelist.asns = process.env.BOT_DETECTION_WHITELIST_ASNS.split(',').map(asn => parseInt(asn.trim(), 10));
        }
        if (process.env.BOT_DETECTION_WHITELIST_MONITORING_TOOLS !== undefined) {
            // This would be handled by the WhitelistManager configuration
        }

        // Required headers
        if (process.env.BOT_DETECTION_REQUIRED_HEADERS !== undefined) {
            config.fingerprinting.requiredHeaders = process.env.BOT_DETECTION_REQUIRED_HEADERS.split(',').map(h => h.trim());
        }
    }

    /**
     * Validate configuration values
     */
    private validateConfiguration(config: DetectionConfig): void {
        // Validate scoring weights
        const weights = config.scoringWeights;
        if (weights.fingerprint < 0 || weights.fingerprint > 1) {
            throw new ConfigurationError('Fingerprint weight must be between 0 and 1', 'scoringWeights.fingerprint');
        }
        if (weights.behavioral < 0 || weights.behavioral > 1) {
            throw new ConfigurationError('Behavioral weight must be between 0 and 1', 'scoringWeights.behavioral');
        }
        if (weights.geographic < 0 || weights.geographic > 1) {
            throw new ConfigurationError('Geographic weight must be between 0 and 1', 'scoringWeights.geographic');
        }
        if (weights.reputation < 0 || weights.reputation > 1) {
            throw new ConfigurationError('Reputation weight must be between 0 and 1', 'scoringWeights.reputation');
        }

        // Validate that weights sum to approximately 1
        const totalWeight = weights.fingerprint + weights.behavioral + weights.geographic + weights.reputation;
        if (Math.abs(totalWeight - 1.0) > 0.001) {
            throw new ConfigurationError(`Scoring weights must sum to 1.0, got ${totalWeight}`, 'scoringWeights');
        }

        // Validate thresholds
        if (config.thresholds.suspicious < 0 || config.thresholds.suspicious > 100) {
            throw new ConfigurationError('Suspicious threshold must be between 0 and 100', 'thresholds.suspicious');
        }
        if (config.thresholds.highRisk < 0 || config.thresholds.highRisk > 100) {
            throw new ConfigurationError('High risk threshold must be between 0 and 100', 'thresholds.highRisk');
        }
        if (config.thresholds.suspicious >= config.thresholds.highRisk) {
            throw new ConfigurationError('Suspicious threshold must be less than high risk threshold', 'thresholds');
        }

        // Validate behavioral settings
        if (config.behavioral.minHumanInterval < 0) {
            throw new ConfigurationError('Minimum human interval must be non-negative', 'behavioral.minHumanInterval');
        }
        if (config.behavioral.maxConsistency < 0 || config.behavioral.maxConsistency > 1) {
            throw new ConfigurationError('Max consistency must be between 0 and 1', 'behavioral.maxConsistency');
        }
        if (config.behavioral.sessionTimeout < 0) {
            throw new ConfigurationError('Session timeout must be non-negative', 'behavioral.sessionTimeout');
        }

        // Validate geographic settings
        if (config.geographic.vpnPenalty < 0 || config.geographic.vpnPenalty > 100) {
            throw new ConfigurationError('VPN penalty must be between 0 and 100', 'geographic.vpnPenalty');
        }
        if (config.geographic.hostingPenalty < 0 || config.geographic.hostingPenalty > 100) {
            throw new ConfigurationError('Hosting penalty must be between 0 and 100', 'geographic.hostingPenalty');
        }

        // Validate required headers
        if (config.fingerprinting.requiredHeaders.length === 0) {
            throw new ConfigurationError('At least one required header must be specified', 'fingerprinting.requiredHeaders');
        }
    }

    /**
     * Merge configuration objects
     */
    private mergeConfig(base: DetectionConfig, updates: Partial<DetectionConfig>): DetectionConfig {
        return {
            enabled: updates.enabled ?? base.enabled,
            scoringWeights: {
                ...base.scoringWeights,
                ...updates.scoringWeights,
            },
            thresholds: {
                ...base.thresholds,
                ...updates.thresholds,
            },
            fingerprinting: {
                ...base.fingerprinting,
                ...updates.fingerprinting,
            },
            behavioral: {
                ...base.behavioral,
                ...updates.behavioral,
            },
            geographic: {
                ...base.geographic,
                ...updates.geographic,
            },
            whitelist: {
                ...base.whitelist,
                ...updates.whitelist,
            },
        };
    }

    /**
     * Check if configuration has changed
     */
    private hasConfigChanged(oldConfig: DetectionConfig, newConfig: DetectionConfig): boolean {
        return JSON.stringify(oldConfig) !== JSON.stringify(newConfig);
    }

    /**
     * Get configuration changes for logging
     */
    private getConfigChanges(oldConfig: DetectionConfig, newConfig: DetectionConfig): Record<string, any> {
        const changes: Record<string, any> = {};

        // Simple deep comparison for logging changes
        const compareObjects = (old: any, updated: any, path: string = '') => {
            for (const key in updated) {
                const currentPath = path ? `${path}.${key}` : key;
                if (typeof updated[key] === 'object' && updated[key] !== null && !Array.isArray(updated[key])) {
                    compareObjects(old[key] || {}, updated[key], currentPath);
                } else if (JSON.stringify(old[key]) !== JSON.stringify(updated[key])) {
                    changes[currentPath] = {
                        from: old[key],
                        to: updated[key],
                    };
                }
            }
        };

        compareObjects(oldConfig, newConfig);
        return changes;
    }

    /**
     * Cleanup resources
     */
    destroy(): void {
        this.stopWatching();
        this.removeAllListeners();
    }
}

// Singleton instance
let configManager: ConfigurationManager | null = null;

/**
 * Get the global configuration manager instance
 */
export function getConfigurationManager(): ConfigurationManager {
    if (!configManager) {
        configManager = new ConfigurationManager();
    }
    return configManager;
}

/**
 * Initialize configuration manager with custom settings
 */
export function initializeConfigurationManager(configPath?: string): ConfigurationManager {
    if (configManager) {
        configManager.destroy();
    }
    configManager = new ConfigurationManager(configPath);
    return configManager;
}