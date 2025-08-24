import { Reader, open } from 'maxmind';
import { GeoLocation } from '../types/GeoLocation.js';
import { join } from 'path';
import { dirname } from '../../utils/filesystemConstants.js';
import { createWriteStream, existsSync, mkdirSync, statSync } from 'fs';
import { pipeline } from 'stream/promises';

/**
 * Configuration interface for geographic analysis
 */
interface GeographicConfig {
    /** List of country codes considered high risk */
    highRiskCountries: string[];
    /** Score penalty for VPN usage (0-100) */
    vpnPenalty: number;
    /** Score penalty for hosting provider IPs (0-100) */
    hostingPenalty: number;
}

/**
 * Geographic analysis service for IP addresses
 * Provides location data, infrastructure detection, and risk scoring
 */
export class GeoAnalyzer {
    private geoDatabase: Reader<any> | null = null;
    private asnDatabase: Reader<any> | null = null;
    private initialized = false;
    private static databasesEnsured = false;

    // Configuration
    private readonly highRiskCountries: string[];
    private readonly vpnPenalty: number;
    private readonly hostingPenalty: number;

    // MaxMind database download URLs
    private readonly GEOLITE2_CITY_URL = 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb';
    private readonly GEOLITE2_ASN_URL = 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb';

    // Default high-risk countries
    private static readonly DEFAULT_HIGH_RISK_COUNTRIES = [
        'CN', 'RU', 'KP', 'IR', 'SY', 'AF', 'IQ', 'LY', 'SO', 'SD'
    ];

    // Known hosting/cloud provider ASNs (partial list)
    private readonly HOSTING_ASNS = new Set([
        13335, // Cloudflare
        16509, // Amazon AWS
        15169, // Google Cloud
        8075,  // Microsoft Azure
        14061, // DigitalOcean
        20473, // Choopa (Vultr)
        24940, // Hetzner
        16276, // OVH
        36351, // SoftLayer (IBM Cloud)
        63949, // Linode
    ]);

    // Known VPN provider patterns in organization names
    private readonly VPN_PATTERNS = [
        /vpn/i,
        /proxy/i,
        /tunnel/i,
        /private.*internet/i,
        /nordvpn/i,
        /expressvpn/i,
        /surfshark/i,
        /cyberghost/i,
        /purevpn/i,
        /hotspot.*shield/i,
    ];

    /**
     * Constructor for BehaviorAnalyzer
     */
    constructor(config?: GeographicConfig) {
        this.highRiskCountries = config?.highRiskCountries || GeoAnalyzer.DEFAULT_HIGH_RISK_COUNTRIES
        this.vpnPenalty = config?.vpnPenalty || 25;
        this.hostingPenalty = config?.hostingPenalty || 15;
    }

    /**
     * Get database paths from environment variables or defaults
     */
    private getDatabasePaths(): { geoPath: string; asnPath: string } {
        // Check environment variables first
        const envGeoPath = process.env.GEOLITE2_CITY_DB_PATH;
        const envAsnPath = process.env.GEOLITE2_ASN_DB_PATH;

        if (envGeoPath && envAsnPath) {
            return {
                geoPath: envGeoPath,
                asnPath: envAsnPath
            };
        }

        // Fall back to default paths
        const defaultGeoDbPath = join(dirname, '../data/geoip/GeoLite2-City.mmdb');
        const defaultAsnDbPath = join(dirname, '../data/geoip/GeoLite2-ASN.mmdb');

        return {
            geoPath: envGeoPath || defaultGeoDbPath,
            asnPath: envAsnPath || defaultAsnDbPath
        };
    }

    /**
     * Ensure databases are downloaded (should be called once on server start)
     * @param forceDownload Force re-download even if files exist
     */
    static async ensureDatabases(forceDownload = false): Promise<void> {
        if (GeoAnalyzer.databasesEnsured && !forceDownload) {
            return;
        }

        const analyzer = new GeoAnalyzer();
        const { geoPath, asnPath } = analyzer.getDatabasePaths();

        try {
            // Ensure the directory exists
            const dbDir = join(dirname, '../data/geoip');
            if (!existsSync(dbDir)) {
                mkdirSync(dbDir, { recursive: true });
            }

            // Download databases if they don't exist or if forced
            await analyzer.ensureDatabaseExists(geoPath, analyzer.GEOLITE2_CITY_URL, forceDownload);
            await analyzer.ensureDatabaseExists(asnPath, analyzer.GEOLITE2_ASN_URL, forceDownload);

            GeoAnalyzer.databasesEnsured = true;
            console.log('GeoAnalyzer databases ensured successfully');
        } catch (error) {
            console.error('Failed to ensure GeoAnalyzer databases:', error);
            // Don't throw - allow fallback to simulation mode
        }
    }

    /**
     * Initialize the GeoAnalyzer with MaxMind databases
     * @param geoDbPath Path to GeoLite2-City.mmdb file (overrides env variables)
     * @param asnDbPath Path to GeoLite2-ASN.mmdb file (overrides env variables)
     */
    async initialize(geoDbPath?: string, asnDbPath?: string): Promise<void> {
        try {
            // Get database paths (from env vars or defaults)
            const { geoPath: defaultGeoPath, asnPath: defaultAsnPath } = this.getDatabasePaths();

            // Use provided paths or defaults from env/config
            const geoPath = geoDbPath || defaultGeoPath;
            const asnPath = asnDbPath || defaultAsnPath;

            // Open the MaxMind databases
            this.geoDatabase = await open(geoPath);
            this.asnDatabase = await open(asnPath);

            this.initialized = true;
            console.log('GeoAnalyzer initialized successfully with MaxMind databases');
        } catch (error) {
            console.error('Failed to initialize GeoAnalyzer:', error);
            // Fall back to simulation mode if databases are not available
            this.initialized = true;
            console.log('GeoAnalyzer initialized in simulation mode (MaxMind databases not available)');
        }
    }

    /**
     * Ensure a database file exists, downloading it if necessary
     * @param filePath Path where the database should be stored
     * @param downloadUrl URL to download the database from
     * @param forceDownload Force re-download even if file exists
     */
    async ensureDatabaseExists(filePath: string, downloadUrl: string, forceDownload = false): Promise<void> {
        const shouldDownload = forceDownload || !existsSync(filePath) || this.isDatabaseStale(filePath);

        if (shouldDownload) {
            console.log(`Downloading MaxMind database from ${downloadUrl}...`);
            await this.downloadDatabase(downloadUrl, filePath);
            console.log(`Database downloaded successfully to ${filePath}`);
        }
    }

    /**
     * Check if a database file is stale (older than 30 days)
     * @param filePath Path to the database file
     * @returns True if the file is stale or doesn't exist
     */
    private isDatabaseStale(filePath: string): boolean {
        if (!existsSync(filePath)) {
            return true;
        }

        try {
            const stats = statSync(filePath);
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

            return stats.mtime < thirtyDaysAgo;
        } catch (error) {
            console.warn(`Could not check file stats for ${filePath}:`, error);
            return true;
        }
    }

    /**
     * Download a database file from a URL
     * @param url URL to download from
     * @param filePath Path to save the file to
     */
    private async downloadDatabase(url: string, filePath: string): Promise<void> {
        try {
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            if (!response.body) {
                throw new Error('Response body is null');
            }

            const fileStream = createWriteStream(filePath);

            // Use pipeline to handle the stream properly
            await pipeline(response.body as any, fileStream);

        } catch (error) {
            console.error(`Failed to download database from ${url}:`, error);
            throw error;
        }
    }

    /**
     * Analyze an IP address for geographic and infrastructure information
     * @param ip IP address to analyze
     * @returns Promise resolving to GeoLocation data
     */
    async analyze(ip: string): Promise<GeoLocation> {
        if (!this.initialized) {
            throw new Error('GeoAnalyzer not initialized. Call initialize() first.');
        }

        try {
            // Validate IP address format
            if (!this.isValidIP(ip)) {
                return this.createDefaultGeoLocation(ip);
            }

            // For localhost and private IPs, return default data
            if (this.isPrivateIP(ip)) {
                return this.createLocalGeoLocation();
            }

            // Query the MaxMind databases or fall back to simulation
            const geoData = await this.lookupGeoData(ip);
            const asnData = await this.lookupASNData(ip);

            const geoLocation: GeoLocation = {
                country: geoData.country,
                region: geoData.region,
                city: geoData.city,
                isVPN: this.detectVPN(asnData.organization),
                isProxy: this.detectProxy(asnData.organization),
                isHosting: this.detectHosting(asnData.asn, asnData.organization),
                isTor: this.detectTor(ip, asnData.organization),
                riskScore: 0, // Will be calculated below
                asn: asnData.asn,
                organization: asnData.organization,
            };

            // Calculate risk score based on all factors
            geoLocation.riskScore = this.calculateGeoRisk(geoLocation);

            return geoLocation;
        } catch (error) {
            console.error('Error analyzing IP:', ip, error);
            return this.createDefaultGeoLocation(ip);
        }
    }

    /**
     * Calculate geographic risk score based on location and infrastructure factors
     * @param location GeoLocation data
     * @returns Risk score from 0-100
     */
    private calculateGeoRisk(location: GeoLocation): number {
        let riskScore = 0;

        // Base risk from country
        if (this.highRiskCountries.includes(location.country)) {
            riskScore += 30;
        }

        // Infrastructure-based risk
        if (location.isVPN) {
            riskScore += this.vpnPenalty;
        }
        if (location.isProxy) {
            riskScore += 20;
        }
        if (location.isHosting) {
            riskScore += this.hostingPenalty;
        }
        if (location.isTor) {
            riskScore += 40;
        }

        // Cap at 100
        return Math.min(riskScore, 100);
    }

    /**
     * Detect if an organization is a VPN provider
     */
    private detectVPN(organization: string): boolean {
        return this.VPN_PATTERNS.some(pattern => pattern.test(organization));
    }

    /**
     * Detect if an organization is a proxy provider
     */
    private detectProxy(organization: string): boolean {
        return /proxy/i.test(organization) || /anonymizer/i.test(organization);
    }

    /**
     * Detect if an ASN/organization is a hosting provider
     */
    private detectHosting(asn: number, organization: string): boolean {
        if (this.HOSTING_ASNS.has(asn)) {
            return true;
        }

        const hostingPatterns = [
            /hosting/i,
            /cloud/i,
            /server/i,
            /datacenter/i,
            /colocation/i,
            /vps/i,
            /dedicated/i,
        ];

        return hostingPatterns.some(pattern => pattern.test(organization));
    }

    /**
     * Detect if an IP is a Tor exit node
     */
    private detectTor(_ip: string, organization: string): boolean {
        // In a real implementation, this would check against Tor exit node lists
        return /tor/i.test(organization) || /onion/i.test(organization);
    }

    /**
     * Validate IP address format
     */
    private isValidIP(ip: string): boolean {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        // More flexible IPv6 regex that handles compressed notation like ::1
        const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::)$/;

        if (ipv4Regex.test(ip)) {
            const parts = ip.split('.');
            return parts.every(part => parseInt(part) >= 0 && parseInt(part) <= 255);
        }

        return ipv6Regex.test(ip) || ip.includes(':');
    }

    /**
     * Check if IP is private/local
     */
    private isPrivateIP(ip: string): boolean {
        if (ip === '127.0.0.1' || ip === '::1') {
            return true;
        }

        // Check IPv6 private ranges
        if (ip.includes(':')) {
            return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80');
        }

        const parts = ip.split('.');
        if (parts.length === 4) {
            const first = parseInt(parts[0]);
            const second = parseInt(parts[1]);

            // Private IP ranges
            return (
                first === 10 ||
                (first === 172 && second >= 16 && second <= 31) ||
                (first === 192 && second === 168)
            );
        }

        return false;
    }

    /**
     * Create default GeoLocation for invalid/unknown IPs
     */
    private createDefaultGeoLocation(_ip: string): GeoLocation {
        return {
            country: 'unknown',
            region: 'unknown',
            city: 'unknown',
            isVPN: false,
            isProxy: false,
            isHosting: false,
            isTor: false,
            riskScore: 0,
            asn: 0,
            organization: 'unknown',
        };
    }

    /**
     * Create GeoLocation for local/private IPs
     */
    private createLocalGeoLocation(): GeoLocation {
        return {
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
        };
    }

    /**
     * Lookup geographic data using MaxMind database
     */
    private async lookupGeoData(ip: string): Promise<{ country: string, region: string, city: string }> {
        if (this.geoDatabase) {
            try {
                const result = this.geoDatabase.get(ip);
                if (result) {
                    return {
                        country: result.country?.iso_code || 'unknown',
                        region: result.subdivisions?.[0]?.names?.en || result.subdivisions?.[0]?.iso_code || 'unknown',
                        city: result.city?.names?.en || 'unknown',
                    };
                }
            } catch (error) {
                console.warn('MaxMind geo lookup failed for IP:', ip, error);
            }
        }

        // Fall back to simulation if database is not available or lookup fails
        return this.simulateGeoLookup(ip);
    }

    /**
     * Lookup ASN data using MaxMind database
     */
    private async lookupASNData(ip: string): Promise<{ asn: number, organization: string }> {
        if (this.asnDatabase) {
            try {
                const result = this.asnDatabase.get(ip);
                if (result) {
                    return {
                        asn: result.autonomous_system_number || 0,
                        organization: result.autonomous_system_organization || 'unknown',
                    };
                }
            } catch (error) {
                console.warn('MaxMind ASN lookup failed for IP:', ip, error);
            }
        }

        // Fall back to simulation if database is not available or lookup fails
        return this.simulateASNLookup(ip);
    }

    /**
     * Simulate geo database lookup (fallback when MaxMind database is not available)
     */
    private async simulateGeoLookup(ip: string): Promise<{ country: string, region: string, city: string }> {
        const hash = this.simpleHash(ip);
        const countries = ['US', 'GB', 'DE', 'FR', 'JP', 'CN', 'RU', 'BR', 'IN', 'AU'];
        const regions = ['California', 'London', 'Bavaria', 'Ile-de-France', 'Tokyo', 'Beijing', 'Moscow', 'Sao Paulo', 'Maharashtra', 'New South Wales'];
        const cities = ['San Francisco', 'London', 'Munich', 'Paris', 'Tokyo', 'Beijing', 'Moscow', 'Sao Paulo', 'Mumbai', 'Sydney'];

        const index = hash % countries.length;

        return {
            country: countries[index],
            region: regions[index],
            city: cities[index],
        };
    }

    /**
     * Simulate ASN database lookup (fallback when MaxMind database is not available)
     */
    private async simulateASNLookup(ip: string): Promise<{ asn: number, organization: string }> {
        const hash = this.simpleHash(ip);
        const asns = [13335, 16509, 15169, 8075, 14061, 20473, 24940, 16276, 36351, 63949];
        const orgs = [
            'Cloudflare Inc',
            'Amazon AWS',
            'Google LLC',
            'Microsoft Corporation',
            'DigitalOcean LLC',
            'Choopa LLC',
            'Hetzner Online GmbH',
            'OVH SAS',
            'SoftLayer Technologies',
            'Linode LLC'
        ];

        const index = hash % asns.length;

        return {
            asn: asns[index],
            organization: orgs[index],
        };
    }

    /**
     * Simple hash function for simulation
     */
    private simpleHash(str: string): number {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash);
    }

    /**
     * Check if the analyzer is initialized
     */
    isInitialized(): boolean {
        return this.initialized;
    }

    /**
     * Check if using real MaxMind databases or simulation mode
     */
    isUsingRealDatabases(): boolean {
        return this.geoDatabase !== null && this.asnDatabase !== null;
    }

    /**
     * Force update the MaxMind databases by re-downloading them
     */
    async updateDatabases(): Promise<void> {
        console.log('Forcing update of MaxMind databases...');
        await GeoAnalyzer.ensureDatabases(true);
        // Re-initialize to load the updated databases
        await this.initialize();
    }

    /**
     * Get analyzer version information
     */
    getVersion(): string {
        return '1.0.1';
    }
}