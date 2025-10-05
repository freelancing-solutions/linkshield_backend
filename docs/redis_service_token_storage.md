# Redis Service Token Storage Implementation

## Overview

The Redis Service Token Storage system provides persistent, scalable storage for service authentication tokens in the LinkShield backend. This implementation replaces the previous in-memory token storage with a Redis-based solution that includes comprehensive error handling and fallback mechanisms.

## Architecture

### Core Components

1. **ServiceTokenStorage** (`src/auth/service_token_storage.py`)
   - Primary Redis-based token storage implementation
   - Handles token lifecycle: creation, validation, usage tracking, revocation, cleanup
   - Includes fallback to in-memory storage when Redis is unavailable

2. **BotAuthenticator** (`src/auth/bot_auth.py`)
   - Updated to use ServiceTokenStorage for persistent token management
   - Maintains backward compatibility with existing API
   - Enhanced error handling for Redis failures

### Key Features

- **Persistent Storage**: Tokens survive application restarts
- **Scalability**: Supports multiple application instances
- **Fallback Mechanism**: Graceful degradation to in-memory storage
- **Comprehensive Error Handling**: Robust handling of Redis connection issues
- **Usage Tracking**: Detailed statistics and monitoring capabilities
- **Automatic Cleanup**: Background cleanup of expired tokens

## Token Structure

### Token Data Format
```json
{
    "service_name": "string",
    "permissions": ["permission1", "permission2"],
    "created_at": "2024-01-01T00:00:00Z",
    "expires_at": "2024-01-01T01:00:00Z",
    "max_uses": 100,
    "current_uses": 5,
    "last_used_at": "2024-01-01T00:30:00Z"
}
```

### Redis Key Structure
- **Token Storage**: `service_token:{token_id}`
- **Service Index**: `service_index:{service_name}` (Set of token IDs)
- **Expiration Index**: `expiration_index:{timestamp}` (Set of token IDs)
- **Statistics**: `service_token_stats` (Hash of counters)

## API Reference

### ServiceTokenStorage Methods

#### `store_token(service_name, permissions, expires_in, max_uses)`
Creates and stores a new service token.

**Parameters:**
- `service_name` (str): Name of the requesting service
- `permissions` (List[str]): List of permissions granted to the token
- `expires_in` (int): Token lifetime in seconds (default: 3600)
- `max_uses` (Optional[int]): Maximum usage count (default: None)

**Returns:** Token string

**Raises:** `ServiceTokenStorageError` on storage failure

#### `get_token(token)`
Retrieves and validates a token.

**Parameters:**
- `token` (str): Token string to retrieve

**Returns:** Token data dictionary

**Raises:** 
- `TokenNotFoundError`: Token doesn't exist
- `TokenExpiredError`: Token has expired
- `ServiceTokenStorageError`: Storage operation failed

#### `update_token_usage(token)`
Updates token usage statistics.

**Parameters:**
- `token` (str): Token string to update

**Raises:** `TokenNotFoundError`, `ServiceTokenStorageError`

#### `revoke_token(token)`
Revokes a token immediately.

**Parameters:**
- `token` (str): Token string to revoke

**Raises:** `TokenNotFoundError`, `ServiceTokenStorageError`

#### `cleanup_expired_tokens()`
Removes all expired tokens from storage.

**Returns:** Number of tokens cleaned up

#### `get_service_token_stats(service_name)`
Retrieves token statistics.

**Parameters:**
- `service_name` (Optional[str]): Filter by service name

**Returns:** Statistics dictionary

### BotAuthenticator Methods

#### `generate_service_token(service_name, permissions, expires_in, max_uses)`
Generates a new service token with Redis persistence.

#### `validate_service_token(token)`
Validates a service token and updates usage.

**Returns:** Tuple of (is_valid, token_data_or_error)

#### `revoke_service_token(token)`
Revokes a service token.

**Returns:** Boolean success status

#### `cleanup_expired_tokens()`
Cleans up expired tokens.

**Returns:** Number of tokens cleaned up

## Error Handling

### Exception Hierarchy
```
ServiceTokenStorageError (Base)
├── TokenNotFoundError
├── TokenExpiredError
└── RedisConnectionError
```

### Fallback Mechanism

When Redis is unavailable:
1. Operations automatically fall back to in-memory storage
2. `_redis_available` flag tracks Redis status
3. Periodic reconnection attempts restore Redis functionality
4. Statistics include both Redis and fallback data

### Error Recovery

- **Connection Failures**: Automatic fallback to in-memory storage
- **Timeout Errors**: Logged and handled gracefully
- **Data Corruption**: Individual token failures don't affect others
- **Redis Unavailable**: Full fallback mode with logging

## Configuration

### Redis Settings
Configure Redis connection in `src/config/settings.py`:

```python
REDIS_URL = "redis://localhost:6379/0"
REDIS_TIMEOUT = 5.0
REDIS_RETRY_ATTEMPTS = 3
```

### Token Settings
```python
DEFAULT_TOKEN_EXPIRY = 3600  # 1 hour
MAX_TOKEN_USES = None        # Unlimited by default
CLEANUP_INTERVAL = 300       # 5 minutes
```

## Monitoring and Statistics

### Available Metrics
- `total_tokens`: Total active tokens
- `active_tokens`: Currently valid tokens
- `tokens_stored`: Cumulative tokens created
- `tokens_retrieved`: Cumulative token retrievals
- `tokens_used`: Cumulative token usage updates
- `tokens_revoked`: Cumulative token revocations
- `tokens_cleaned`: Cumulative expired tokens cleaned
- `redis_available`: Redis connection status
- `fallback_tokens`: Tokens in fallback storage

### Usage Example
```python
# Get overall statistics
stats = await service_token_storage.get_service_token_stats()

# Get statistics for specific service
service_stats = await service_token_storage.get_service_token_stats("api_service")
```

## Migration Guide

### From In-Memory to Redis

1. **Backup Existing Tokens**: Export current in-memory tokens if needed
2. **Update Dependencies**: Ensure Redis is available and configured
3. **Deploy Changes**: The system automatically handles the transition
4. **Monitor Fallback**: Check logs for any Redis connection issues

### Backward Compatibility

The implementation maintains full backward compatibility:
- Existing API methods unchanged
- Same return types and error handling
- Graceful fallback ensures no service interruption

## Performance Considerations

### Redis Operations
- **Token Storage**: O(1) for individual operations
- **Service Indexing**: O(log N) for set operations
- **Cleanup**: O(N) where N is number of expired tokens
- **Statistics**: O(1) for most metrics

### Memory Usage
- **Redis**: Approximately 1KB per token
- **Fallback**: Same as previous in-memory implementation
- **Indexes**: Minimal overhead for service and expiration tracking

### Scalability
- Supports thousands of concurrent tokens
- Horizontal scaling through Redis clustering
- Efficient cleanup prevents memory bloat

## Security Considerations

### Token Security
- Tokens are cryptographically secure (64-character hex)
- No sensitive data stored in Redis keys
- Automatic expiration prevents token accumulation

### Access Control
- Redis access should be restricted to application servers
- Use Redis AUTH if available
- Consider Redis SSL/TLS for production

### Audit Trail
- All token operations are logged
- Usage statistics provide audit capabilities
- Failed operations are tracked and logged

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   - Check Redis server status
   - Verify connection settings
   - Review network connectivity
   - System falls back to in-memory storage

2. **Token Not Found**
   - Token may have expired
   - Check if token was revoked
   - Verify token format and validity

3. **Performance Issues**
   - Monitor Redis memory usage
   - Check cleanup frequency
   - Review token expiration settings

### Debugging

Enable debug logging:
```python
import logging
logging.getLogger('src.auth.service_token_storage').setLevel(logging.DEBUG)
```

### Health Checks

Monitor system health:
```python
# Check Redis availability
stats = await service_token_storage.get_service_token_stats()
redis_available = stats['redis_available']

# Check fallback usage
fallback_count = stats['fallback_tokens']
```

## Future Enhancements

### Planned Features
- Token refresh capabilities
- Advanced permission scoping
- Token usage analytics
- Distributed rate limiting
- Cross-service token sharing

### Optimization Opportunities
- Token compression for large permission sets
- Batch operations for bulk token management
- Redis pipeline optimization
- Advanced caching strategies

## Conclusion

The Redis Service Token Storage implementation provides a robust, scalable solution for service authentication in the LinkShield backend. With comprehensive error handling, fallback mechanisms, and detailed monitoring, it ensures reliable token management even in adverse conditions.

The system maintains backward compatibility while adding significant improvements in persistence, scalability, and observability. The fallback mechanism ensures zero-downtime operation, making it suitable for production environments with high availability requirements.