# Enhanced Bot Detection Middleware

The Enhanced Bot Detection middleware provides sophisticated bot detection capabilities that go beyond simple user-agent checking. It analyzes HTTP fingerprints, behavioral patterns, and geographic information to create comprehensive threat assessments.

## Features

- **HTTP Fingerprinting**: Analyzes request headers, patterns, and automation signatures
- **Behavioral Analysis**: Tracks request timing, navigation patterns, and human-like behavior
- **Geographic Intelligence**: Uses GeoIP data to identify VPNs, proxies, and high-risk locations
- **Threat Scoring**: Combines multiple factors into a weighted suspicion score (0-100)
- **Performance Monitoring**: Built-in timeout handling and performance metrics
- **Configurable**: Extensive configuration options for different environments
- **Integration Ready**: Works seamlessly with existing Express middleware

## Quick Start

```typescript
import { enhancedBotDetectionMiddleware } from './middleware/enhancedBotDetection.js';
import { tarpit } from './middleware/tarpit.js';

const app = express();

// IP extraction (required)
app.use((req, res, next) => {
    req.realIp = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || 
                 req.socket.remoteAddress || 'unknown';
    next();
});

// Enhanced bot detection
app.use(enhancedBotDetectionMiddleware);

// Tarpit middleware (enhanced with detection results)
app.use(tarpit);
```

## Configuration

The middleware accepts a configuration object with the following options:

```typescript
const config: DetectionConfig = {
    enabled: true,
    scoringWeights: {
        fingerprint: 0.3,    // HTTP fingerprinting weight
        behavioral: 0.3,     // Behavioral analysis weight
        geographic: 0.2,     // Geographic analysis weight
        reputation: 0.2      // Reputation analysis weight
    },
    thresholds: {
        suspicious: 30,      // Threshold for suspicious requests
        highRisk: 70        // Threshold for high-risk requests
    },
    fingerprinting: {
        requiredHeaders: ['Accept', 'Accept-Language', 'Accept-Encoding'],
        suspiciousPatterns: [/python-requests/i, /curl/i, /bot/i],
        automationSignatures: [/selenium/i, /puppeteer/i, /headless/i]
    },
    behavioral: {
        minHumanInterval: 500,    // Minimum time between requests (ms)
        maxConsistency: 0.8,      // Maximum timing consistency
        sessionTimeout: 1800000   // Session timeout (30 minutes)
    },
    geographic: {
        highRiskCountries: ['CN', 'RU', 'KP', 'IR'],
        vpnPenalty: 20,
        hostingPenalty: 15
    },
    whitelist: {
        ips: ['127.0.0.1'],
        userAgents: [/GoogleBot/i, /BingBot/i],
        asns: []
    }
};

const middleware = new EnhancedBotDetectionMiddleware(config);
app.use(middleware.middleware);
```

## Detection Results

The middleware adds detection information to the request object:

```typescript
app.use((req, res, next) => {
    if (req.detectionResult) {
        console.log('Suspicion Score:', req.detectionResult.suspicionScore);
        console.log('Confidence:', req.detectionResult.confidence);
        console.log('Reasons:', req.detectionResult.reasons);
        console.log('Fingerprint:', req.detectionResult.fingerprint);
    }
    
    if (req.suspiciousRequest) {
        console.log('Request flagged as suspicious');
    }
    
    next();
});
```

## Response Headers

For suspicious requests, the middleware sets response headers:

- `X-Detection-Score`: Suspicion score (0-100)
- `X-Detection-Confidence`: Confidence level (0-1)
- `X-Detection-Fingerprint`: Unique request fingerprint

## Integration with Existing Middleware

### Tarpit Middleware

The enhanced tarpit middleware now uses detection results for more precise delays:

```typescript
// Before: Fixed delays based on request count
// After: Dynamic delays based on suspicion score

if (suspicionScore > 50) {
    delay = (suspicionScore - 30) * 375; // 1-15 seconds based on score
}
```

### Rate Limiting

The middleware sets flags that can be used by downstream middleware:

```typescript
if (req.suspiciousRequest) {
    // Apply stricter rate limiting
    return strictLimiter(req, res, next);
}
```

## Performance

- **Processing Time**: < 50ms per request (with timeout protection)
- **Memory Usage**: Efficient LRU caching for session data
- **Fallback**: Graceful degradation when services are unavailable
- **Monitoring**: Built-in performance metrics and logging

## Error Handling

The middleware includes comprehensive error handling:

- **GeoIP Service Failures**: Falls back to default geographic data
- **Analysis Timeouts**: Returns fallback results after 50ms
- **Invalid Configurations**: Validates settings on startup
- **Network Issues**: Continues processing with reduced functionality

## Logging

The middleware provides structured logging:

```typescript
// Suspicious requests
[Enhanced Detection] Suspicious request from 192.168.1.100: {
  path: '/api/data',
  score: 65,
  confidence: 0.8,
  processingTime: 25.5,
  reasons: 3,
  fingerprint: 'abc123...'
}

// Threat alerts
SUSPICIOUS_BOT_DETECTED from python-requests/2.28.1 -> /api/data {
  data: {
    score: 65,
    confidence: 0.8,
    reasons: ['Missing headers', 'Automation detected'],
    fingerprint: 'abc123...'
  }
}
```

## Testing

The middleware includes comprehensive unit tests:

```bash
npm test -- --testPathPatterns=enhancedBotDetection.unit.test.ts
```

Test coverage includes:
- Basic functionality and whitelisting
- Detection capabilities (suspicious UAs, automation, missing headers)
- Error handling and graceful degradation
- Configuration management
- Performance under load

## Advanced Usage

### Custom Configuration

```typescript
const middleware = new EnhancedBotDetectionMiddleware(customConfig);

// Update configuration at runtime
middleware.updateConfig({
    thresholds: { suspicious: 40, highRisk: 80 }
});

// Get performance statistics
const stats = middleware.getPerformanceStats();
console.log('Average processing time:', stats.averageProcessingTime);
```

### Manual Analysis

```typescript
// Analyze a specific request manually
const result = await middleware.performAnalysis(req, ip);
console.log('Manual analysis result:', result);
```

## Security Considerations

- **Timing Attacks**: Consistent response times prevent timing-based detection
- **Log Injection**: All logged data is sanitized
- **Resource Limits**: Built-in memory management and cleanup
- **Configuration Security**: Secure defaults for all settings

## Troubleshooting

### Common Issues

1. **High False Positives**: Adjust `thresholds.suspicious` or add to whitelist
2. **GeoIP Errors**: Ensure GeoLite2 databases are available
3. **Performance Issues**: Check `maxProcessingTime` and enable caching
4. **Missing Detection Results**: Verify middleware order and IP extraction

### Debug Mode

Enable detailed logging in development:

```typescript
process.env.NODE_ENV = 'development';
// Logs all requests, including legitimate ones
```

## Migration from Legacy Detection

To migrate from the existing `isKnownBot` function:

1. Install the enhanced middleware before existing bot detection
2. Gradually increase detection thresholds
3. Monitor false positive rates
4. Remove legacy detection once confident

```typescript
// Before
app.use((req, res, next) => {
    if (isKnownBot(req.headers['user-agent'])) {
        return generateFaultyResponse(res);
    }
    next();
});

// After
app.use(enhancedBotDetectionMiddleware);
// Legacy detection is now handled automatically
```