# Enhanced Bot Detection System

## Configuration Management

The Enhanced Bot Detection System includes a comprehensive configuration management system that supports environment variables, validation, and hot-reloading.

### Quick Start

```typescript
import { getConfigurationManager } from './ConfigurationManager';

// Get the global configuration manager
const configManager = getConfigurationManager();

// Get current configuration
const config = configManager.getConfig();

// Update configuration
configManager.updateConfig({
    thresholds: {
        suspicious: 25,
        highRisk: 75,
    },
});

// Listen for configuration changes
configManager.on('configChanged', (newConfig, oldConfig) => {
    console.log('Configuration updated!');
});
```

### Environment Variables

All configuration options can be set via environment variables:

#### Main Settings
- `BOT_DETECTION_ENABLED` - Enable/disable the detection system (default: `true`)

#### Scoring Weights (must sum to 1.0)
- `BOT_DETECTION_WEIGHT_FINGERPRINT` - HTTP fingerprinting weight (default: `0.3`)
- `BOT_DETECTION_WEIGHT_BEHAVIORAL` - Behavioral analysis weight (default: `0.3`)
- `BOT_DETECTION_WEIGHT_GEOGRAPHIC` - Geographic analysis weight (default: `0.2`)
- `BOT_DETECTION_WEIGHT_REPUTATION` - Reputation analysis weight (default: `0.2`)

#### Detection Thresholds (0-100)
- `BOT_DETECTION_THRESHOLD_SUSPICIOUS` - Suspicious threshold (default: `30`)
- `BOT_DETECTION_THRESHOLD_HIGH_RISK` - High risk threshold (default: `70`)

#### Behavioral Analysis
- `BOT_DETECTION_MIN_HUMAN_INTERVAL` - Minimum human-like interval in ms (default: `500`)
- `BOT_DETECTION_MAX_CONSISTENCY` - Maximum timing consistency (0-1, default: `0.8`)
- `BOT_DETECTION_SESSION_TIMEOUT` - Session timeout in ms (default: `1800000`)

#### Geographic Analysis
- `BOT_DETECTION_HIGH_RISK_COUNTRIES` - Comma-separated country codes (default: `CN,RU,KP,IR`)
- `BOT_DETECTION_VPN_PENALTY` - VPN penalty score (0-100, default: `20`)
- `BOT_DETECTION_HOSTING_PENALTY` - Hosting provider penalty (0-100, default: `15`)

#### Whitelist Settings
- `BOT_DETECTION_WHITELIST_IPS` - Comma-separated IP addresses
- `BOT_DETECTION_WHITELIST_ASNS` - Comma-separated ASN numbers
- `BOT_DETECTION_REQUIRED_HEADERS` - Comma-separated required headers

### Configuration Validation

The system validates all configuration values:

- **Scoring weights** must be between 0 and 1 and sum to 1.0
- **Thresholds** must be between 0 and 100, with suspicious < high risk
- **Behavioral settings** must have non-negative intervals and valid consistency scores
- **Geographic penalties** must be between 0 and 100
- **Required headers** list cannot be empty

### Hot-Reloading

Enable automatic configuration reloading:

```typescript
// Start watching for changes every 5 seconds
configManager.startWatching(5000);

// Stop watching
configManager.stopWatching();
```

### Error Handling

Configuration errors are thrown as `ConfigurationError` instances:

```typescript
import { ConfigurationError } from './ConfigurationManager';

try {
    configManager.updateConfig({
        thresholds: { suspicious: 80, highRisk: 60 }, // Invalid: suspicious > highRisk
    });
} catch (error) {
    if (error instanceof ConfigurationError) {
        console.log('Configuration error:', error.message);
        console.log('Field:', error.field);
    }
}
```

### Example Configuration File

Create a `.env` file with your configuration:

```bash
# Enhanced Bot Detection Configuration
BOT_DETECTION_ENABLED=true

# Scoring Weights (must sum to 1.0)
BOT_DETECTION_WEIGHT_FINGERPRINT=0.4
BOT_DETECTION_WEIGHT_BEHAVIORAL=0.3
BOT_DETECTION_WEIGHT_GEOGRAPHIC=0.2
BOT_DETECTION_WEIGHT_REPUTATION=0.1

# Detection Thresholds
BOT_DETECTION_THRESHOLD_SUSPICIOUS=25
BOT_DETECTION_THRESHOLD_HIGH_RISK=75

# Geographic Settings
BOT_DETECTION_HIGH_RISK_COUNTRIES=CN,RU,KP,IR,VN
BOT_DETECTION_VPN_PENALTY=25
BOT_DETECTION_HOSTING_PENALTY=20

# Whitelist
BOT_DETECTION_WHITELIST_IPS=127.0.0.1,::1,192.168.1.100
BOT_DETECTION_WHITELIST_ASNS=15169,8075
```

### Integration with Detection System

The configuration manager integrates seamlessly with the detection system:

```typescript
import { getConfigurationManager } from './ConfigurationManager';
import { ThreatScoringEngine } from './ThreatScoringEngine';

const configManager = getConfigurationManager();
const config = configManager.getConfig();

// Use configuration in threat scoring
const scoringEngine = new ThreatScoringEngine(config.scoringWeights);

// Update scoring engine when configuration changes
configManager.on('configChanged', (newConfig) => {
    scoringEngine.updateWeights(newConfig.scoringWeights);
});
```

### Best Practices

1. **Use environment variables** for production deployments
2. **Enable hot-reloading** in development environments
3. **Listen for configuration changes** to update dependent components
4. **Validate configuration** before deployment
5. **Use the singleton pattern** (`getConfigurationManager()`) for consistency
6. **Handle configuration errors** gracefully
7. **Document custom configurations** for your team

### Testing

The configuration system includes comprehensive tests covering:

- Environment variable loading
- Configuration validation
- Hot-reloading functionality
- Error handling
- Singleton behavior

Run tests with:
```bash
npm test -- --testPathPatterns=ConfigurationManager.test.ts
```