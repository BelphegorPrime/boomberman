import type {
    DetectionResult,
    DetectionReason,
    DetectionMetadata,
    HTTPFingerprint,
    BehaviorMetrics,
    GeoLocation,
    ScoringWeights,
} from './types/index.js';

/**
 * Engine for calculating threat scores based on multiple detection factors
 */
export class ThreatScoringEngine {
    private readonly weights: ScoringWeights;
    private readonly version = '1.0.0';

    constructor(weights: ScoringWeights) {
        this.weights = this.validateWeights(weights);
    }

    /**
     * Calculate comprehensive threat score from all detection factors
     */
    calculateScore(
        fingerprint: HTTPFingerprint,
        behavior: BehaviorMetrics,
        geo: GeoLocation,
        reputation?: number
    ): DetectionResult {
        const startTime = process.hrtime.bigint();
        const reasons: DetectionReason[] = [];

        // Calculate individual scores
        const fingerprintScore = this.calculateFingerprintScore(fingerprint, reasons);
        const behaviorScore = this.calculateBehaviorScore(behavior, reasons);
        const geoScore = this.calculateGeoScore(geo, reasons);
        const reputationScore = reputation || 0;

        if (reputation && reputation > 0) {
            reasons.push({
                category: 'reputation',
                severity: reputation > 50 ? 'high' : reputation > 25 ? 'medium' : 'low',
                description: `IP has reputation score of ${reputation}`,
                score: reputation,
            });
        }

        // Combine scores using weighted algorithm
        const combinedScore = this.combineScores(
            [fingerprintScore, behaviorScore, geoScore, reputationScore],
            [this.weights.fingerprint, this.weights.behavioral, this.weights.geographic, this.weights.reputation]
        );

        // Calculate confidence based on available data quality
        const confidence = this.determineConfidence([fingerprintScore, behaviorScore, geoScore, reputationScore]);

        // Generate unique fingerprint
        const requestFingerprint = this.generateFingerprint(fingerprint, behavior, geo);

        const endTime = process.hrtime.bigint();
        const processingTime = Number(endTime - startTime) / 1_000_000; // Convert to milliseconds

        const metadata: DetectionMetadata = {
            timestamp: Date.now(),
            processingTime: Math.round(processingTime * 100) / 100,
            detectorVersions: {
                threatScoringEngine: this.version,
            },
            geoData: geo,
            behaviorData: behavior,
        };

        return {
            isSuspicious: combinedScore >= 30, // Default suspicious threshold
            suspicionScore: Math.round(combinedScore),
            confidence: Math.round(confidence * 100) / 100,
            reasons,
            fingerprint: requestFingerprint,
            metadata,
        };
    }

    /**
     * Calculate score based on HTTP fingerprinting analysis
     */
    private calculateFingerprintScore(fingerprint: HTTPFingerprint, reasons: DetectionReason[]): number {
        let score = 0;

        // Missing headers penalty
        if (fingerprint.missingHeaders.length > 0) {
            const penalty = Math.min(fingerprint.missingHeaders.length * 10, 40);
            score += penalty;
            reasons.push({
                category: 'fingerprint',
                severity: penalty > 30 ? 'high' : penalty > 15 ? 'medium' : 'low',
                description: `Missing ${fingerprint.missingHeaders.length} common browser headers: ${fingerprint.missingHeaders.join(', ')}`,
                score: penalty,
            });
        }

        // Suspicious headers penalty
        if (fingerprint.suspiciousHeaders.length > 0) {
            const penalty = Math.min(fingerprint.suspiciousHeaders.length * 15, 50);
            score += penalty;
            reasons.push({
                category: 'fingerprint',
                severity: penalty > 35 ? 'high' : penalty > 20 ? 'medium' : 'low',
                description: `Suspicious headers detected: ${fingerprint.suspiciousHeaders.join(', ')}`,
                score: penalty,
            });
        }

        // Header order score (lower is more suspicious)
        if (fingerprint.headerOrderScore < 0.5) {
            const penalty = (1 - fingerprint.headerOrderScore) * 30;
            score += penalty;
            reasons.push({
                category: 'fingerprint',
                severity: penalty > 20 ? 'high' : penalty > 10 ? 'medium' : 'low',
                description: `Unusual header order pattern (score: ${fingerprint.headerOrderScore.toFixed(2)})`,
                score: penalty,
            });
        }

        // Automation signatures penalty
        if (fingerprint.automationSignatures.length > 0) {
            const penalty = 80; // High penalty for automation detection
            score += penalty;
            reasons.push({
                category: 'fingerprint',
                severity: 'high',
                description: `Automation framework detected: ${fingerprint.automationSignatures.join(', ')}`,
                score: penalty,
            });
        }

        return Math.min(score, 100);
    }

    /**
     * Calculate score based on behavioral analysis
     */
    private calculateBehaviorScore(behavior: BehaviorMetrics, reasons: DetectionReason[]): number {
        let score = 0;

        // Sub-human request intervals
        if (behavior.requestInterval < 500) {
            const penalty = Math.max(0, (500 - behavior.requestInterval) / 10);
            score += penalty;
            reasons.push({
                category: 'behavioral',
                severity: penalty > 30 ? 'high' : penalty > 15 ? 'medium' : 'low',
                description: `Sub-human request interval: ${behavior.requestInterval}ms`,
                score: penalty,
            });
        }

        // High timing consistency (robotic behavior)
        if (behavior.timingConsistency > 0.8) {
            const penalty = (behavior.timingConsistency - 0.8) * 100;
            score += penalty;
            reasons.push({
                category: 'behavioral',
                severity: penalty > 15 ? 'high' : penalty > 8 ? 'medium' : 'low',
                description: `Highly consistent timing pattern (${(behavior.timingConsistency * 100).toFixed(1)}% consistency)`,
                score: penalty,
            });
        }

        // Low human-like score
        if (behavior.humanLikeScore < 0.3) {
            const penalty = (0.3 - behavior.humanLikeScore) * 100;
            score += penalty;
            reasons.push({
                category: 'behavioral',
                severity: penalty > 20 ? 'high' : penalty > 10 ? 'medium' : 'low',
                description: `Low human-like behavior score: ${(behavior.humanLikeScore * 100).toFixed(1)}%`,
                score: penalty,
            });
        }

        // Suspicious navigation patterns
        if (behavior.navigationPattern.length > 0) {
            const suspiciousPatterns = behavior.navigationPattern.filter(pattern =>
                pattern.includes('admin') ||
                pattern.includes('api') ||
                pattern.includes('login') ||
                pattern.includes('wp-') ||
                pattern.includes('.php')
            );

            if (suspiciousPatterns.length > 0) {
                const penalty = Math.min(suspiciousPatterns.length * 10, 30);
                score += penalty;
                reasons.push({
                    category: 'behavioral',
                    severity: penalty > 20 ? 'high' : penalty > 10 ? 'medium' : 'low',
                    description: `Suspicious navigation pattern detected: ${suspiciousPatterns.join(', ')}`,
                    score: penalty,
                });
            }
        }

        return Math.min(score, 100);
    }

    /**
     * Calculate score based on geographic analysis
     */
    private calculateGeoScore(geo: GeoLocation, reasons: DetectionReason[]): number {
        let score = geo.riskScore; // Base score from GeoAnalyzer

        // VPN/Proxy penalties
        if (geo.isVPN) {
            score += 20;
            reasons.push({
                category: 'geographic',
                severity: 'medium',
                description: 'Request originates from VPN endpoint',
                score: 20,
            });
        }

        if (geo.isProxy) {
            score += 15;
            reasons.push({
                category: 'geographic',
                severity: 'medium',
                description: 'Request originates from proxy server',
                score: 15,
            });
        }

        if (geo.isHosting) {
            score += 15;
            reasons.push({
                category: 'geographic',
                severity: 'medium',
                description: `Request originates from hosting provider: ${geo.organization}`,
                score: 15,
            });
        }

        if (geo.isTor) {
            score += 25;
            reasons.push({
                category: 'geographic',
                severity: 'high',
                description: 'Request originates from Tor exit node',
                score: 25,
            });
        }

        return Math.min(score, 100);
    }

    /**
     * Combine multiple scores using weighted algorithm
     */
    private combineScores(scores: number[], weights: number[]): number {
        if (scores.length !== weights.length) {
            throw new Error('Scores and weights arrays must have the same length');
        }

        // Normalize weights to sum to 1
        const totalWeight = weights.reduce((sum, weight) => sum + weight, 0);
        const normalizedWeights = weights.map(weight => weight / totalWeight);

        // Calculate weighted average
        let weightedSum = 0;
        let totalUsedWeight = 0;

        for (let i = 0; i < scores.length; i++) {
            if (scores[i] >= 0) { // Include zero scores as valid data
                weightedSum += scores[i] * normalizedWeights[i];
                totalUsedWeight += normalizedWeights[i];
            }
        }

        // If no scores available, return 0
        if (totalUsedWeight === 0) {
            return 0;
        }

        // Normalize by actual used weights
        const finalScore = weightedSum / totalUsedWeight;

        // Apply non-linear scaling for extreme cases
        return this.applyNonLinearScaling(finalScore);
    }

    /**
     * Apply non-linear scaling to emphasize extreme scores
     */
    private applyNonLinearScaling(score: number): number {
        // Use sigmoid-like function to emphasize high scores
        if (score > 70) {
            return Math.min(100, score + (score - 70) * 0.5);
        }
        return score;
    }

    /**
     * Determine confidence level based on available data quality
     */
    private determineConfidence(scores: number[]): number {
        // Base confidence on number of available data sources (include zero scores as available data)
        const availableDataSources = scores.filter(score => score >= 0).length;
        const maxDataSources = scores.length;

        let confidence = availableDataSources / maxDataSources;

        // Boost confidence if multiple sources agree on high threat
        const highScores = scores.filter(score => score > 50).length;
        if (highScores >= 2) {
            confidence = Math.min(1.0, confidence + 0.2);
        }

        // Reduce confidence if scores are conflicting
        const lowScores = scores.filter(score => score < 20).length;
        const highScoreCount = scores.filter(score => score > 60).length;
        if (lowScores > 0 && highScoreCount > 0) {
            confidence *= 0.8;
        }

        return Math.max(0.1, Math.min(1.0, confidence));
    }

    /**
     * Generate unique fingerprint for the request
     */
    private generateFingerprint(fingerprint: HTTPFingerprint, behavior: BehaviorMetrics, geo: GeoLocation): string {
        const components = [
            fingerprint.headerSignature,
            behavior.timingConsistency.toFixed(2),
            behavior.humanLikeScore.toFixed(2),
            geo.country,
            geo.asn.toString(),
            geo.isVPN ? 'vpn' : '',
            geo.isProxy ? 'proxy' : '',
            geo.isHosting ? 'hosting' : '',
        ].filter(Boolean);

        // Create hash-like fingerprint
        return components.join('|').replace(/[^a-zA-Z0-9|]/g, '').substring(0, 32);
    }

    /**
     * Validate and normalize scoring weights
     */
    private validateWeights(weights: ScoringWeights): ScoringWeights {
        const { fingerprint, behavioral, geographic, reputation } = weights;

        // Ensure all weights are positive
        if (fingerprint < 0 || behavioral < 0 || geographic < 0 || reputation < 0) {
            throw new Error('All scoring weights must be non-negative');
        }

        // Ensure at least one weight is positive
        if (fingerprint + behavioral + geographic + reputation === 0) {
            throw new Error('At least one scoring weight must be positive');
        }

        return weights;
    }

    /**
     * Update scoring weights
     */
    updateWeights(newWeights: ScoringWeights): void {
        const validatedWeights = this.validateWeights(newWeights);
        Object.assign(this.weights, validatedWeights);
    }

    /**
     * Get current scoring weights
     */
    getWeights(): ScoringWeights {
        return { ...this.weights };
    }
}