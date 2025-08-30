import { EventEmitter } from 'events';
import type { Request } from 'express';
import type { GeoLocation } from './types/GeoLocation.js';

/**
 * Whitelist entry types
 */
export interface WhitelistEntry {
    id: string;
    type: 'ip' | 'userAgent' | 'asn' | 'fingerprint';
    value: string | number | RegExp;
    description?: string;
    addedBy: string;
    addedAt: number;
    expiresAt?: number;
    isActive: boolean;
    metadata?: Record<string, any>;
}

/**
 * Whitelist configuration interface
 */
export interface WhitelistConfig {
    /** IP addresses to whitelist */
    ips: string[];
    /** User-agent patterns to whitelist */
    userAgents: RegExp[];
    /** ASN numbers to whitelist */
    asns: number[];
    /** Request fingerprints to whitelist */
    fingerprints: string[];
    /** Enable automatic whitelist for known monitoring tools */
    enableMonitoringToolsBypass: boolean;
    /** Maximum number of whitelist entries */
    maxEntries: number;
    /** Default expiration time for temporary entries (ms) */
    defaultExpirationTime: number;
}

/**
 * Whitelist check result
 */
export interface WhitelistResult {
    isWhitelisted: boolean;
    matchedEntries: WhitelistEntry[];
    reason: string;
    bypassType: 'ip' | 'userAgent' | 'asn' | 'fingerprint' | 'monitoring' | 'none';
}

/**
 * Known monitoring tools and legitimate bots
 */
const MONITORING_TOOLS: Array<{ pattern: RegExp; description: string }> = [
    { pattern: /GoogleBot/i, description: 'Google Search Bot' },
    { pattern: /BingBot/i, description: 'Microsoft Bing Bot' },
    { pattern: /Slackbot/i, description: 'Slack Link Preview Bot' },
    { pattern: /facebookexternalhit/i, description: 'Facebook Link Preview Bot' },
    { pattern: /Twitterbot/i, description: 'Twitter Link Preview Bot' },
    { pattern: /LinkedInBot/i, description: 'LinkedIn Bot' },
    { pattern: /WhatsApp/i, description: 'WhatsApp Link Preview' },
    { pattern: /TelegramBot/i, description: 'Telegram Bot' },
    { pattern: /DiscordBot/i, description: 'Discord Bot' },
    { pattern: /AppleBot/i, description: 'Apple Search Bot' },
    { pattern: /DuckDuckBot/i, description: 'DuckDuckGo Bot' },
    { pattern: /YandexBot/i, description: 'Yandex Search Bot' },
    { pattern: /BaiduSpider/i, description: 'Baidu Search Bot' },
    { pattern: /UptimeRobot/i, description: 'Uptime Monitoring Service' },
    { pattern: /Pingdom/i, description: 'Pingdom Monitoring Service' },
    { pattern: /StatusCake/i, description: 'StatusCake Monitoring Service' },
    { pattern: /Site24x7/i, description: 'Site24x7 Monitoring Service' },
    { pattern: /NewRelic/i, description: 'New Relic Monitoring Service' },
    { pattern: /DatadogSynthetics/i, description: 'Datadog Synthetic Monitoring' },
];

/**
 * Comprehensive whitelist management system
 */
export class WhitelistManager extends EventEmitter {
    private entries: Map<string, WhitelistEntry> = new Map();
    private config: WhitelistConfig;
    private cleanupInterval?: NodeJS.Timeout;

    constructor(config: Partial<WhitelistConfig> = {}) {
        super();

        this.config = {
            ips: [],
            userAgents: [],
            asns: [],
            fingerprints: [],
            enableMonitoringToolsBypass: true,
            maxEntries: 10000,
            defaultExpirationTime: 24 * 60 * 60 * 1000, // 24 hours
            ...config,
        };

        // Initialize with default entries
        this.initializeDefaultEntries();

        // Start cleanup interval for expired entries
        this.startCleanupInterval();
    }

    /**
     * Initialize default whitelist entries
     */
    private initializeDefaultEntries(): void {
        // Add configured IPs
        this.config.ips.forEach(ip => {
            this.addEntry({
                type: 'ip',
                value: ip,
                description: 'Default IP whitelist entry',
                addedBy: 'system',
                permanent: true,
            });
        });

        // Add configured user agents
        this.config.userAgents.forEach(pattern => {
            this.addEntry({
                type: 'userAgent',
                value: pattern,
                description: 'Default user-agent whitelist entry',
                addedBy: 'system',
                permanent: true,
            });
        });

        // Add configured ASNs
        this.config.asns.forEach(asn => {
            this.addEntry({
                type: 'asn',
                value: asn,
                description: 'Default ASN whitelist entry',
                addedBy: 'system',
                permanent: true,
            });
        });

        // Add configured fingerprints
        this.config.fingerprints.forEach(fingerprint => {
            this.addEntry({
                type: 'fingerprint',
                value: fingerprint,
                description: 'Default fingerprint whitelist entry',
                addedBy: 'system',
                permanent: true,
            });
        });
    }

    /**
     * Check if a request should be whitelisted
     */
    checkWhitelist(
        req: Request,
        ip: string,
        userAgent: string,
        geoData?: GeoLocation,
        fingerprint?: string
    ): WhitelistResult {
        const matchedEntries: WhitelistEntry[] = [];
        let bypassType: WhitelistResult['bypassType'] = 'none';
        let reason = '';

        // Normalize IP address (remove IPv6 prefix if present)
        const normalizedIp = ip.replace(/^::ffff:/, '');

        // Check IP whitelist
        const ipMatches = this.findMatchingEntries('ip', [normalizedIp, ip]);
        if (ipMatches.length > 0) {
            matchedEntries.push(...ipMatches);
            bypassType = 'ip';
            reason = `IP ${normalizedIp} is whitelisted`;
        }

        // Check user-agent whitelist
        if (userAgent) {
            const uaMatches = this.findMatchingUserAgentEntries(userAgent);
            if (uaMatches.length > 0) {
                matchedEntries.push(...uaMatches);
                if (bypassType === 'none') {
                    bypassType = 'userAgent';
                    reason = `User-agent "${userAgent}" matches whitelist pattern`;
                }
            }

            // Check monitoring tools bypass
            if (this.config.enableMonitoringToolsBypass) {
                const monitoringMatch = this.checkMonitoringTools(userAgent);
                if (monitoringMatch) {
                    if (bypassType === 'none') {
                        bypassType = 'monitoring';
                        reason = `Legitimate monitoring tool detected: ${monitoringMatch.description}`;
                    }
                }
            }
        }

        // Check ASN whitelist
        if (geoData?.asn) {
            const asnMatches = this.findMatchingEntries('asn', [geoData.asn]);
            if (asnMatches.length > 0) {
                matchedEntries.push(...asnMatches);
                if (bypassType === 'none') {
                    bypassType = 'asn';
                    reason = `ASN ${geoData.asn} is whitelisted`;
                }
            }
        }

        // Check fingerprint whitelist
        if (fingerprint) {
            const fingerprintMatches = this.findMatchingEntries('fingerprint', [fingerprint]);
            if (fingerprintMatches.length > 0) {
                matchedEntries.push(...fingerprintMatches);
                if (bypassType === 'none') {
                    bypassType = 'fingerprint';
                    reason = `Request fingerprint is whitelisted`;
                }
            }
        }

        const isWhitelisted = matchedEntries.length > 0 || bypassType === 'monitoring';

        // Log whitelist check if whitelisted
        if (isWhitelisted) {
            this.emit('whitelistMatch', {
                ip: normalizedIp,
                userAgent,
                matchedEntries,
                bypassType,
                reason,
                timestamp: Date.now(),
            });
        }

        return {
            isWhitelisted,
            matchedEntries,
            reason,
            bypassType,
        };
    }

    /**
     * Add a new whitelist entry
     */
    addEntry(options: {
        type: WhitelistEntry['type'];
        value: string | number | RegExp;
        description?: string;
        addedBy: string;
        expirationTime?: number;
        permanent?: boolean;
        metadata?: Record<string, any>;
    }): string {
        // Check if we've reached the maximum number of entries
        if (this.entries.size >= this.config.maxEntries) {
            throw new Error(`Maximum whitelist entries (${this.config.maxEntries}) reached`);
        }

        const id = this.generateEntryId(options.type, options.value);
        const now = Date.now();

        const entry: WhitelistEntry = {
            id,
            type: options.type,
            value: options.value,
            description: options.description,
            addedBy: options.addedBy,
            addedAt: now,
            expiresAt: options.permanent ? undefined : (now + (options.expirationTime || this.config.defaultExpirationTime)),
            isActive: true,
            metadata: options.metadata,
        };

        this.entries.set(id, entry);

        this.emit('entryAdded', entry);

        return id;
    }

    /**
     * Remove a whitelist entry
     */
    removeEntry(id: string, removedBy: string = 'system'): boolean {
        const entry = this.entries.get(id);
        if (!entry) {
            return false;
        }

        this.entries.delete(id);

        this.emit('entryRemoved', {
            entry,
            removedBy,
            removedAt: Date.now(),
        });

        return true;
    }

    /**
     * Update a whitelist entry
     */
    updateEntry(id: string, updates: Partial<WhitelistEntry>, updatedBy: string = 'system'): boolean {
        const entry = this.entries.get(id);
        if (!entry) {
            return false;
        }

        const oldEntry = { ...entry };
        Object.assign(entry, updates);

        this.emit('entryUpdated', {
            oldEntry,
            newEntry: entry,
            updatedBy,
            updatedAt: Date.now(),
        });

        return true;
    }

    /**
     * Get all whitelist entries
     */
    getAllEntries(): WhitelistEntry[] {
        return Array.from(this.entries.values());
    }

    /**
     * Get entries by type
     */
    getEntriesByType(type: WhitelistEntry['type']): WhitelistEntry[] {
        return Array.from(this.entries.values()).filter(entry => entry.type === type);
    }

    /**
     * Get active entries (non-expired)
     */
    getActiveEntries(): WhitelistEntry[] {
        const now = Date.now();
        return Array.from(this.entries.values()).filter(entry =>
            entry.isActive && (!entry.expiresAt || entry.expiresAt > now)
        );
    }

    /**
     * Find matching entries for given values
     */
    private findMatchingEntries(type: WhitelistEntry['type'], values: (string | number)[]): WhitelistEntry[] {
        const now = Date.now();
        const matches: WhitelistEntry[] = [];

        for (const entry of this.entries.values()) {
            if (entry.type !== type || !entry.isActive) {
                continue;
            }

            // Check if entry is expired
            if (entry.expiresAt && entry.expiresAt <= now) {
                continue;
            }

            // Check for matches
            for (const value of values) {
                if (entry.value === value) {
                    matches.push(entry);
                    break;
                }
            }
        }

        return matches;
    }

    /**
     * Find matching user-agent entries (supports RegExp patterns)
     */
    private findMatchingUserAgentEntries(userAgent: string): WhitelistEntry[] {
        const now = Date.now();
        const matches: WhitelistEntry[] = [];

        for (const entry of this.entries.values()) {
            if (entry.type !== 'userAgent' || !entry.isActive) {
                continue;
            }

            // Check if entry is expired
            if (entry.expiresAt && entry.expiresAt <= now) {
                continue;
            }

            // Check for matches (support both string and RegExp)
            if (entry.value instanceof RegExp) {
                if (entry.value.test(userAgent)) {
                    matches.push(entry);
                }
            } else if (typeof entry.value === 'string') {
                if (userAgent.includes(entry.value)) {
                    matches.push(entry);
                }
            }
        }

        return matches;
    }

    /**
     * Check if user-agent matches known monitoring tools
     */
    private checkMonitoringTools(userAgent: string): { pattern: RegExp; description: string } | null {
        for (const tool of MONITORING_TOOLS) {
            if (tool.pattern.test(userAgent)) {
                return tool;
            }
        }
        return null;
    }

    /**
     * Generate unique entry ID
     */
    private generateEntryId(type: WhitelistEntry['type'], value: string | number | RegExp): string {
        const valueStr = value instanceof RegExp ? value.source : String(value);
        const hash = this.simpleHash(valueStr);
        return `${type}-${hash}-${Date.now()}`;
    }

    /**
     * Simple hash function for generating IDs
     */
    private simpleHash(str: string): string {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(36);
    }

    /**
     * Start cleanup interval for expired entries
     */
    private startCleanupInterval(): void {
        // Run cleanup every hour
        this.cleanupInterval = setInterval(() => {
            this.cleanupExpiredEntries();
        }, 60 * 60 * 1000);
    }

    /**
     * Clean up expired entries
     */
    private cleanupExpiredEntries(): void {
        const now = Date.now();
        const expiredEntries: WhitelistEntry[] = [];

        for (const [id, entry] of this.entries.entries()) {
            if (entry.expiresAt && entry.expiresAt <= now) {
                expiredEntries.push(entry);
                this.entries.delete(id);
            }
        }

        if (expiredEntries.length > 0) {
            this.emit('entriesExpired', {
                expiredEntries,
                cleanupAt: now,
            });
        }
    }

    /**
     * Clear system-added entries (for config updates)
     */
    private clearSystemEntries(): void {
        for (const [id, entry] of this.entries) {
            if (entry.addedBy === 'system') {
                this.entries.delete(id);
            }
        }
    }

    /**
     * Update configuration
     */
    updateConfig(newConfig: Partial<WhitelistConfig>): void {
        const oldConfig = { ...this.config };
        this.config = { ...this.config, ...newConfig };

        // Clear existing system entries and reinitialize with new config
        // But only if we have room for the new entries
        this.clearSystemEntries();

        // Calculate how many entries we would add
        const potentialEntries = this.config.ips.length +
            this.config.userAgents.length +
            this.config.asns.length +
            this.config.fingerprints.length;

        // Only reinitialize if we have room, otherwise skip to avoid exceeding maxEntries
        if (this.entries.size + potentialEntries <= this.config.maxEntries) {
            this.initializeDefaultEntries();
        }

        this.emit('configUpdated', {
            oldConfig,
            newConfig: this.config,
            updatedAt: Date.now(),
        });
    }

    /**
     * Get whitelist statistics
     */
    getStatistics(): {
        totalEntries: number;
        activeEntries: number;
        expiredEntries: number;
        entriesByType: Record<string, number>;
        oldestEntry: number | null;
        newestEntry: number | null;
    } {
        const now = Date.now();
        const allEntries = Array.from(this.entries.values());
        const activeEntries = allEntries.filter(entry =>
            entry.isActive && (!entry.expiresAt || entry.expiresAt > now)
        );
        const expiredEntries = allEntries.filter(entry =>
            entry.expiresAt && entry.expiresAt <= now
        );

        const entriesByType: Record<string, number> = {};
        for (const entry of activeEntries) {
            entriesByType[entry.type] = (entriesByType[entry.type] || 0) + 1;
        }

        const timestamps = allEntries.map(entry => entry.addedAt);
        const oldestEntry = timestamps.length > 0 ? Math.min(...timestamps) : null;
        const newestEntry = timestamps.length > 0 ? Math.max(...timestamps) : null;

        return {
            totalEntries: allEntries.length,
            activeEntries: activeEntries.length,
            expiredEntries: expiredEntries.length,
            entriesByType,
            oldestEntry,
            newestEntry,
        };
    }

    /**
     * Export whitelist entries for backup
     */
    exportEntries(): WhitelistEntry[] {
        return Array.from(this.entries.values()).map(entry => ({
            ...entry,
            // Convert RegExp to string for serialization
            value: entry.value instanceof RegExp ? entry.value.source : entry.value,
        }));
    }

    /**
     * Import whitelist entries from backup
     */
    importEntries(entries: WhitelistEntry[], importedBy: string = 'system'): number {
        let importedCount = 0;

        for (const entry of entries) {
            try {
                // Convert string back to RegExp for user-agent patterns
                if (entry.type === 'userAgent' && typeof entry.value === 'string') {
                    entry.value = new RegExp(entry.value, 'i');
                }

                this.entries.set(entry.id, {
                    ...entry,
                    addedBy: importedBy,
                    addedAt: Date.now(),
                });
                importedCount++;
            } catch (error) {
                console.warn(`Failed to import whitelist entry ${entry.id}:`, error);
            }
        }

        this.emit('entriesImported', {
            importedCount,
            totalEntries: entries.length,
            importedBy,
            importedAt: Date.now(),
        });

        return importedCount;
    }

    /**
     * Clear all entries
     */
    clearAll(clearedBy: string = 'system'): number {
        const count = this.entries.size;
        this.entries.clear();

        this.emit('allEntriesCleared', {
            clearedCount: count,
            clearedBy,
            clearedAt: Date.now(),
        });

        return count;
    }

    /**
     * Cleanup resources
     */
    destroy(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = undefined;
        }
        this.removeAllListeners();
        this.entries.clear();
    }
}

// Singleton instance
let whitelistManager: WhitelistManager | null = null;

/**
 * Get the global whitelist manager instance
 */
export function getWhitelistManager(): WhitelistManager {
    if (!whitelistManager) {
        whitelistManager = new WhitelistManager();
    }
    return whitelistManager;
}

/**
 * Initialize whitelist manager with custom configuration
 */
export function initializeWhitelistManager(config?: Partial<WhitelistConfig>): WhitelistManager {
    if (whitelistManager) {
        whitelistManager.destroy();
    }
    whitelistManager = new WhitelistManager(config);
    return whitelistManager;
}