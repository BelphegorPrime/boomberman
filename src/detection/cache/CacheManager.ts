import { LRUCache, CacheStats } from './LRUCache.js';
import { GeoLocation } from '../types/GeoLocation.js';
import { SessionData } from '../types/SessionData.js';
import { HTTPFingerprint } from '../types/HTTPFingerprint.js';

/**
 * Configuration for cache manager
 */
export interface CacheConfig {
    /** Maximum number of session entries to cache */
    maxSessionEntries: number;
    /** Maximum number of GeoIP entries to cache */
    maxGeoEntries: number;
    /** Maximum number of fingerprint entries to cache */
    maxFingerprintEntries: number;
    /** Session timeout in milliseconds */
    sessionTimeout: number;
    /** GeoIP cache TTL in milliseconds */
    geoTTL: number;
    /** Fingerprint cache TTL in milliseconds */
    fingerprintTTL: number;
    /** Cleanup interval in milliseconds */
    cleanupInterval: number;
}

/**
 * Cached entry with TTL support
 */
interface CachedEntry<T> {
    value: T;
    timestamp: number;
    ttl: number;
}

/**
 * Cache statistics for monitoring
 */
export interface CacheManagerStats {
    sessions: CacheStats & { hitRate: number; missRate: number };
    geo: CacheStats & { hitRate: number; missRate: number };
    fingerprints: CacheStats & { hitRate: number; missRate: number };
    totalMemoryUsage: number;
    cleanupCount: number;
}

/**
 * Centralized cache manager for detection system
 * Handles session data, GeoIP results, and fingerprint caching with TTL support
 */
export class CacheManager {
    private readonly sessionCache: LRUCache<string, CachedEntry<SessionData>>;
    private readonly geoCache: LRUCache<string, CachedEntry<GeoLocation>>;
    private readonly fingerprintCache: LRUCache<string, CachedEntry<HTTPFingerprint>>;

    private readonly config: CacheConfig;
    private cleanupTimer: NodeJS.Timeout | null = null;

    // Statistics tracking
    private stats = {
        sessions: { hits: 0, misses: 0 },
        geo: { hits: 0, misses: 0 },
        fingerprints: { hits: 0, misses: 0 },
        cleanupCount: 0
    };

    constructor(config?: Partial<CacheConfig>) {
        this.config = {
            maxSessionEntries: config?.maxSessionEntries || 10000,
            maxGeoEntries: config?.maxGeoEntries || 50000,
            maxFingerprintEntries: config?.maxFingerprintEntries || 25000,
            sessionTimeout: config?.sessionTimeout || 30 * 60 * 1000, // 30 minutes
            geoTTL: config?.geoTTL || 24 * 60 * 60 * 1000, // 24 hours
            fingerprintTTL: config?.fingerprintTTL || 60 * 60 * 1000, // 1 hour
            cleanupInterval: config?.cleanupInterval || 5 * 60 * 1000, // 5 minutes
        };

        // Initialize caches
        this.sessionCache = new LRUCache(this.config.maxSessionEntries);
        this.geoCache = new LRUCache(this.config.maxGeoEntries);
        this.fingerprintCache = new LRUCache(this.config.maxFingerprintEntries);

        // Start cleanup timer
        this.startCleanupTimer();
    }

    /**
     * Get session data from cache
     */
    getSession(ip: string): SessionData | undefined {
        const entry = this.sessionCache.get(ip);
        if (!entry) {
            this.stats.sessions.misses++;
            return undefined;
        }

        // Check if entry has expired
        if (this.isExpired(entry)) {
            this.sessionCache.delete(ip);
            this.stats.sessions.misses++;
            return undefined;
        }

        this.stats.sessions.hits++;
        return entry.value;
    }

    /**
     * Set session data in cache
     */
    setSession(ip: string, sessionData: SessionData): void {
        const entry: CachedEntry<SessionData> = {
            value: sessionData,
            timestamp: Date.now(),
            ttl: this.config.sessionTimeout
        };
        this.sessionCache.set(ip, entry);
    }

    /**
     * Update existing session data
     */
    updateSession(ip: string, updateFn: (session: SessionData) => SessionData): void {
        const existing = this.getSession(ip);
        if (existing) {
            const updated = updateFn(existing);
            this.setSession(ip, updated);
        }
    }

    /**
     * Get GeoIP data from cache
     */
    getGeoLocation(ip: string): GeoLocation | undefined {
        const entry = this.geoCache.get(ip);
        if (!entry) {
            this.stats.geo.misses++;
            return undefined;
        }

        // Check if entry has expired
        if (this.isExpired(entry)) {
            this.geoCache.delete(ip);
            this.stats.geo.misses++;
            return undefined;
        }

        this.stats.geo.hits++;
        return entry.value;
    }

    /**
     * Set GeoIP data in cache
     */
    setGeoLocation(ip: string, geoData: GeoLocation): void {
        const entry: CachedEntry<GeoLocation> = {
            value: geoData,
            timestamp: Date.now(),
            ttl: this.config.geoTTL
        };
        this.geoCache.set(ip, entry);
    }

    /**
     * Get fingerprint data from cache
     */
    getFingerprint(fingerprintKey: string): HTTPFingerprint | undefined {
        const entry = this.fingerprintCache.get(fingerprintKey);
        if (!entry) {
            this.stats.fingerprints.misses++;
            return undefined;
        }

        // Check if entry has expired
        if (this.isExpired(entry)) {
            this.fingerprintCache.delete(fingerprintKey);
            this.stats.fingerprints.misses++;
            return undefined;
        }

        this.stats.fingerprints.hits++;
        return entry.value;
    }

    /**
     * Set fingerprint data in cache
     */
    setFingerprint(fingerprintKey: string, fingerprint: HTTPFingerprint): void {
        const entry: CachedEntry<HTTPFingerprint> = {
            value: fingerprint,
            timestamp: Date.now(),
            ttl: this.config.fingerprintTTL
        };
        this.fingerprintCache.set(fingerprintKey, entry);
    }

    /**
     * Generate a cache key for fingerprinting based on relevant headers
     */
    generateFingerprintKey(headers: Record<string, string>): string {
        // Use a subset of headers that are most relevant for fingerprinting
        const relevantHeaders = [
            'user-agent',
            'accept',
            'accept-language',
            'accept-encoding',
            'connection'
        ];

        const keyParts = relevantHeaders
            .map(header => `${header}:${headers[header] || ''}`)
            .join('|');

        // Generate a hash for the key to keep it manageable
        return this.generateHash(keyParts);
    }

    /**
     * Clear expired entries from all caches
     */
    cleanup(): void {
        const now = Date.now();
        let cleanedCount = 0;

        // Cleanup sessions
        for (const key of this.sessionCache.keys()) {
            const entry = this.sessionCache.get(key);
            if (entry && this.isExpired(entry, now)) {
                this.sessionCache.delete(key);
                cleanedCount++;
            }
        }

        // Cleanup geo data
        for (const key of this.geoCache.keys()) {
            const entry = this.geoCache.get(key);
            if (entry && this.isExpired(entry, now)) {
                this.geoCache.delete(key);
                cleanedCount++;
            }
        }

        // Cleanup fingerprints
        for (const key of this.fingerprintCache.keys()) {
            const entry = this.fingerprintCache.get(key);
            if (entry && this.isExpired(entry, now)) {
                this.fingerprintCache.delete(key);
                cleanedCount++;
            }
        }

        this.stats.cleanupCount += cleanedCount;
    }

    /**
     * Get comprehensive cache statistics
     */
    getStats(): CacheManagerStats {
        const sessionStats = this.sessionCache.getStats();
        const geoStats = this.geoCache.getStats();
        const fingerprintStats = this.fingerprintCache.getStats();

        const sessionTotal = this.stats.sessions.hits + this.stats.sessions.misses;
        const geoTotal = this.stats.geo.hits + this.stats.geo.misses;
        const fingerprintTotal = this.stats.fingerprints.hits + this.stats.fingerprints.misses;

        return {
            sessions: {
                ...sessionStats,
                hitRate: sessionTotal > 0 ? this.stats.sessions.hits / sessionTotal : 0,
                missRate: sessionTotal > 0 ? this.stats.sessions.misses / sessionTotal : 0
            },
            geo: {
                ...geoStats,
                hitRate: geoTotal > 0 ? this.stats.geo.hits / geoTotal : 0,
                missRate: geoTotal > 0 ? this.stats.geo.misses / geoTotal : 0
            },
            fingerprints: {
                ...fingerprintStats,
                hitRate: fingerprintTotal > 0 ? this.stats.fingerprints.hits / fingerprintTotal : 0,
                missRate: fingerprintTotal > 0 ? this.stats.fingerprints.misses / fingerprintTotal : 0
            },
            totalMemoryUsage: this.estimateMemoryUsage(),
            cleanupCount: this.stats.cleanupCount
        };
    }

    /**
     * Clear all caches
     */
    clearAll(): void {
        this.sessionCache.clear();
        this.geoCache.clear();
        this.fingerprintCache.clear();

        // Reset statistics
        this.stats = {
            sessions: { hits: 0, misses: 0 },
            geo: { hits: 0, misses: 0 },
            fingerprints: { hits: 0, misses: 0 },
            cleanupCount: 0
        };
    }

    /**
     * Shutdown the cache manager and cleanup resources
     */
    shutdown(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = null;
        }
        this.clearAll();
    }

    /**
     * Check if a cached entry has expired
     */
    private isExpired<T>(entry: CachedEntry<T>, currentTime?: number): boolean {
        const now = currentTime || Date.now();
        return (now - entry.timestamp) > entry.ttl;
    }

    /**
     * Start the cleanup timer
     */
    private startCleanupTimer(): void {
        this.cleanupTimer = setInterval(() => {
            this.cleanup();
        }, this.config.cleanupInterval);
    }

    /**
     * Generate a simple hash for cache keys
     */
    private generateHash(input: string): string {
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(16);
    }

    /**
     * Estimate memory usage of all caches (rough approximation)
     */
    private estimateMemoryUsage(): number {
        // Rough estimation based on cache sizes and average entry sizes
        const avgSessionSize = 2000; // bytes
        const avgGeoSize = 500; // bytes
        const avgFingerprintSize = 1000; // bytes

        return (
            this.sessionCache.getSize() * avgSessionSize +
            this.geoCache.getSize() * avgGeoSize +
            this.fingerprintCache.getSize() * avgFingerprintSize
        );
    }
}