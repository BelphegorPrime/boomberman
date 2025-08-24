import { ConfigurationManager, ConfigurationError, getConfigurationManager, initializeConfigurationManager } from '../src/detection/ConfigurationManager';
import { DetectionConfig, DEFAULT_DETECTION_CONFIG } from '../src/detection/types/Configuration';

describe('ConfigurationManager', () => {
    let configManager: ConfigurationManager;
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach(() => {
        // Save original environment
        originalEnv = { ...process.env };

        // Clear environment variables
        Object.keys(process.env).forEach(key => {
            if (key.startsWith('BOT_DETECTION_')) {
                delete process.env[key];
            }
        });

        configManager = new ConfigurationManager();
    });

    afterEach(() => {
        // Restore original environment
        process.env = originalEnv;

        if (configManager) {
            configManager.destroy();
        }
    });

    describe('constructor', () => {
        it('should initialize with default configuration', () => {
            const config = configManager.getConfig();
            expect(config).toEqual(DEFAULT_DETECTION_CONFIG);
        });

        it('should load configuration from environment variables', () => {
            process.env.BOT_DETECTION_ENABLED = 'false';
            process.env.BOT_DETECTION_THRESHOLD_SUSPICIOUS = '40';
            process.env.BOT_DETECTION_WEIGHT_FINGERPRINT = '0.4';
            process.env.BOT_DETECTION_WEIGHT_BEHAVIORAL = '0.25';
            process.env.BOT_DETECTION_WEIGHT_GEOGRAPHIC = '0.2';
            process.env.BOT_DETECTION_WEIGHT_REPUTATION = '0.15';

            const manager = new ConfigurationManager();
            const config = manager.getConfig();

            expect(config.enabled).toBe(false);
            expect(config.thresholds.suspicious).toBe(40);
            expect(config.scoringWeights.fingerprint).toBe(0.4);

            manager.destroy();
        });
    });

    describe('getConfig', () => {
        it('should return a copy of the configuration', () => {
            const config1 = configManager.getConfig();
            const config2 = configManager.getConfig();

            expect(config1).toEqual(config2);
            expect(config1).not.toBe(config2); // Different objects
        });
    });

    describe('updateConfig', () => {
        it('should update configuration and emit change event', (done) => {
            const newConfig = {
                enabled: false,
                thresholds: { suspicious: 40, highRisk: 80 },
            };

            configManager.on('configChanged', (updatedConfig, oldConfig) => {
                expect(updatedConfig.enabled).toBe(false);
                expect(updatedConfig.thresholds.suspicious).toBe(40);
                expect(updatedConfig.thresholds.highRisk).toBe(80);
                expect(oldConfig.enabled).toBe(true);
                done();
            });

            configManager.updateConfig(newConfig);
        });

        it('should validate configuration before updating', () => {
            const invalidConfig = {
                thresholds: { suspicious: 80, highRisk: 60 }, // Invalid: suspicious > highRisk
            };

            expect(() => {
                configManager.updateConfig(invalidConfig);
            }).toThrow(ConfigurationError);
        });

        it('should merge partial configuration updates', () => {
            const partialUpdate = {
                scoringWeights: { fingerprint: 0.5, behavioral: 0.2, geographic: 0.15, reputation: 0.15 },
            };

            configManager.updateConfig(partialUpdate);
            const config = configManager.getConfig();

            expect(config.scoringWeights.fingerprint).toBe(0.5);
            expect(config.scoringWeights.behavioral).toBe(0.2);
        });
    });

    describe('environment variable loading', () => {
        it('should load boolean values correctly', () => {
            process.env.BOT_DETECTION_ENABLED = 'false';
            const manager = new ConfigurationManager();
            expect(manager.getConfig().enabled).toBe(false);
            manager.destroy();
        });

        it('should load numeric values correctly', () => {
            process.env.BOT_DETECTION_THRESHOLD_SUSPICIOUS = '45';
            process.env.BOT_DETECTION_WEIGHT_FINGERPRINT = '0.35';
            process.env.BOT_DETECTION_WEIGHT_BEHAVIORAL = '0.25';
            process.env.BOT_DETECTION_WEIGHT_GEOGRAPHIC = '0.2';
            process.env.BOT_DETECTION_WEIGHT_REPUTATION = '0.2';

            const manager = new ConfigurationManager();
            const config = manager.getConfig();

            expect(config.thresholds.suspicious).toBe(45);
            expect(config.scoringWeights.fingerprint).toBe(0.35);
            manager.destroy();
        });

        it('should load array values correctly', () => {
            process.env.BOT_DETECTION_HIGH_RISK_COUNTRIES = 'US,CA,GB';
            process.env.BOT_DETECTION_WHITELIST_IPS = '127.0.0.1,192.168.1.1';
            process.env.BOT_DETECTION_WHITELIST_ASNS = '12345,67890';

            const manager = new ConfigurationManager();
            const config = manager.getConfig();

            expect(config.geographic.highRiskCountries).toEqual(['US', 'CA', 'GB']);
            expect(config.whitelist.ips).toEqual(['127.0.0.1', '192.168.1.1']);
            expect(config.whitelist.asns).toEqual([12345, 67890]);
            manager.destroy();
        });

        it('should handle required headers from environment', () => {
            process.env.BOT_DETECTION_REQUIRED_HEADERS = 'Accept,User-Agent,Accept-Language';

            const manager = new ConfigurationManager();
            const config = manager.getConfig();

            expect(config.fingerprinting.requiredHeaders).toEqual(['Accept', 'User-Agent', 'Accept-Language']);
            manager.destroy();
        });
    });

    describe('configuration validation', () => {
        it('should validate scoring weights are between 0 and 1', () => {
            expect(() => {
                configManager.updateConfig({
                    scoringWeights: { fingerprint: 1.5, behavioral: 0.3, geographic: 0.2, reputation: 0.2 },
                });
            }).toThrow(ConfigurationError);

            expect(() => {
                configManager.updateConfig({
                    scoringWeights: { fingerprint: -0.1, behavioral: 0.3, geographic: 0.2, reputation: 0.2 },
                });
            }).toThrow(ConfigurationError);
        });

        it('should validate scoring weights sum to 1', () => {
            expect(() => {
                configManager.updateConfig({
                    scoringWeights: { fingerprint: 0.5, behavioral: 0.5, geographic: 0.5, reputation: 0.5 },
                });
            }).toThrow(ConfigurationError);
        });

        it('should validate thresholds are between 0 and 100', () => {
            expect(() => {
                configManager.updateConfig({
                    thresholds: { suspicious: -10, highRisk: 70 },
                });
            }).toThrow(ConfigurationError);

            expect(() => {
                configManager.updateConfig({
                    thresholds: { suspicious: 30, highRisk: 150 },
                });
            }).toThrow(ConfigurationError);
        });

        it('should validate suspicious threshold is less than high risk threshold', () => {
            expect(() => {
                configManager.updateConfig({
                    thresholds: { suspicious: 80, highRisk: 60 },
                });
            }).toThrow(ConfigurationError);
        });

        it('should validate behavioral settings', () => {
            expect(() => {
                configManager.updateConfig({
                    behavioral: { minHumanInterval: -100, maxConsistency: 0.8, sessionTimeout: 30000 },
                });
            }).toThrow(ConfigurationError);

            expect(() => {
                configManager.updateConfig({
                    behavioral: { minHumanInterval: 500, maxConsistency: 1.5, sessionTimeout: 30000 },
                });
            }).toThrow(ConfigurationError);
        });

        it('should validate geographic settings', () => {
            expect(() => {
                configManager.updateConfig({
                    geographic: { highRiskCountries: ['US'], vpnPenalty: -10, hostingPenalty: 15 },
                });
            }).toThrow(ConfigurationError);

            expect(() => {
                configManager.updateConfig({
                    geographic: { highRiskCountries: ['US'], vpnPenalty: 20, hostingPenalty: 150 },
                });
            }).toThrow(ConfigurationError);
        });

        it('should validate required headers are not empty', () => {
            expect(() => {
                configManager.updateConfig({
                    fingerprinting: {
                        requiredHeaders: [],
                        suspiciousPatterns: [],
                        automationSignatures: [],
                    },
                });
            }).toThrow(ConfigurationError);
        });
    });

    describe('hot-reloading', () => {
        it('should start and stop watching', () => {
            configManager.startWatching(100);
            expect(configManager['watchInterval']).toBeDefined();

            configManager.stopWatching();
            expect(configManager['watchInterval']).toBeUndefined();
        });

        it('should detect configuration changes during watching', (done) => {
            let changeCount = 0;

            configManager.on('configChanged', () => {
                changeCount++;
                if (changeCount === 1) {
                    configManager.stopWatching();
                    done();
                }
            });

            configManager.startWatching(50);

            // Simulate environment change
            setTimeout(() => {
                process.env.BOT_DETECTION_ENABLED = 'false';
            }, 25);
        });
    });

    describe('singleton functions', () => {
        it('should return the same instance from getConfigurationManager', () => {
            const manager1 = getConfigurationManager();
            const manager2 = getConfigurationManager();
            expect(manager1).toBe(manager2);
        });

        it('should create new instance with initializeConfigurationManager', () => {
            const manager1 = getConfigurationManager();
            const manager2 = initializeConfigurationManager();
            expect(manager1).not.toBe(manager2);
        });
    });

    describe('error handling', () => {
        it('should create ConfigurationError with field information', () => {
            const error = new ConfigurationError('Test error', 'test.field');
            expect(error.message).toBe('Test error');
            expect(error.field).toBe('test.field');
            expect(error.name).toBe('ConfigurationError');
        });

        it('should handle invalid environment variable values gracefully', () => {
            process.env.BOT_DETECTION_THRESHOLD_SUSPICIOUS = 'invalid';

            const manager = new ConfigurationManager();
            const config = manager.getConfig();

            // Should fall back to default value
            expect(config.thresholds.suspicious).toBe(DEFAULT_DETECTION_CONFIG.thresholds.suspicious);
            manager.destroy();
        });
    });

    describe('configuration changes tracking', () => {
        it('should track configuration changes for logging', (done) => {
            configManager.on('configChanged', (newConfig, oldConfig) => {
                // Verify that the old and new configs are different
                expect(newConfig.enabled).toBe(false);
                expect(oldConfig.enabled).toBe(true);
                done();
            });

            configManager.updateConfig({ enabled: false });
        });
    });

    describe('destroy', () => {
        it('should cleanup resources when destroyed', () => {
            configManager.startWatching(100);
            const listenerCount = configManager.listenerCount('configChanged');

            configManager.on('configChanged', () => { });
            expect(configManager.listenerCount('configChanged')).toBeGreaterThan(listenerCount);

            configManager.destroy();

            expect(configManager['watchInterval']).toBeUndefined();
            expect(configManager.listenerCount('configChanged')).toBe(0);
        });
    });
});