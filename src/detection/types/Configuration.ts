/**
 * Scoring weights for different detection factors
 */
export interface ScoringWeights {
    /** Weight for HTTP fingerprinting analysis */
    fingerprint: number;
    /** Weight for behavioral analysis */
    behavioral: number;
    /** Weight for geographic analysis */
    geographic: number;
    /** Weight for reputation-based analysis */
    reputation: number;
}

/**
 * Main configuration interface for the enhanced bot detection system
 */
export interface DetectionConfig {
    /** Whether the enhanced detection system is enabled */
    enabled: boolean;
    /** Weights for combining different detection scores */
    scoringWeights: ScoringWeights;
    /** Threshold configuration for different risk levels */
    thresholds: {
        /** Threshold for marking requests as suspicious (0-100) */
        suspicious: number;
        /** Threshold for marking requests as high risk (0-100) */
        highRisk: number;
    };
    /** HTTP fingerprinting configuration */
    fingerprinting: {
        /** Headers that should be present in legitimate browser requests */
        requiredHeaders: string[];
        /** Patterns that indicate suspicious or automated requests */
        suspiciousPatterns: RegExp[];
        /** Signatures of known automation frameworks */
        automationSignatures: RegExp[];
    };
    /** Behavioral analysis configuration */
    behavioral: {
        /** Minimum interval between requests for human-like behavior (ms) */
        minHumanInterval: number;
        /** Maximum timing consistency score before flagging as robotic (0-1) */
        maxConsistency: number;
        /** Session timeout in milliseconds */
        sessionTimeout: number;
    };
    /** Geographic analysis configuration */
    geographic: {
        /** List of country codes considered high risk */
        highRiskCountries: string[];
        /** Score penalty for VPN usage (0-100) */
        vpnPenalty: number;
        /** Score penalty for hosting provider IPs (0-100) */
        hostingPenalty: number;
    };
    /** Whitelist configuration for bypassing detection */
    whitelist: {
        /** IP addresses to whitelist */
        ips: string[];
        /** User-agent patterns to whitelist */
        userAgents: RegExp[];
        /** ASN numbers to whitelist */
        asns: number[];
    };
}

/**
 * Default configuration values for the enhanced bot detection system
 */
export const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
    enabled: true,
    scoringWeights: {
        fingerprint: 0.3,
        behavioral: 0.3,
        geographic: 0.2,
        reputation: 0.2,
    },
    thresholds: {
        suspicious: 30,
        highRisk: 70,
    },
    fingerprinting: {
        requiredHeaders: [
            'Accept',
            'Accept-Language',
            'Accept-Encoding',
            'Connection',
            'Cache-Control',
            'User-Agent',
        ],
        suspiciousPatterns: [
            /python-requests/i,
            /curl/i,
            /wget/i,
            /bot/i,
            /crawler/i,
            /spider/i,
        ],
        automationSignatures: [
            /selenium/i,
            /puppeteer/i,
            /playwright/i,
            /webdriver/i,
            /headless/i,
            /phantom/i,
        ],
    },
    behavioral: {
        minHumanInterval: 500, // 500ms
        maxConsistency: 0.8,
        sessionTimeout: 30 * 60 * 1000, // 30 minutes
    },
    geographic: {
        highRiskCountries: ['CN', 'RU', 'KP', 'IR'],
        vpnPenalty: 20,
        hostingPenalty: 15,
    },
    whitelist: {
        ips: [],
        userAgents: [
            /GoogleBot/i,
            /BingBot/i,
            /Slackbot/i,
            /facebookexternalhit/i,
            /Twitterbot/i,
        ],
        asns: [],
    },
};