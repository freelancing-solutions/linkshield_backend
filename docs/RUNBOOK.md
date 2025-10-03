# LinkShield Social Protection Operations Runbook

## Table of Contents
1. [System Overview](#system-overview)
2. [Monitoring and Health Checks](#monitoring-and-health-checks)
3. [Common Operations](#common-operations)
4. [Troubleshooting](#troubleshooting)
5. [Incident Response](#incident-response)
6. [Maintenance Procedures](#maintenance-procedures)
7. [Emergency Contacts](#emergency-contacts)

## System Overview

### Architecture Components
- **API Layer**: FastAPI application serving REST endpoints
- **Controllers**: UserController, BotController, ExtensionController, CrisisController
- **Services**: SocialScanService, ExtensionDataProcessor, CrisisDetector
- **Analyzers**: ContentRiskAnalyzer, SpamPatternDetector, LinkPenaltyDetector, etc.
- **Platform Adapters**: Twitter, Meta, TikTok, LinkedIn, Telegram, Discord
- **Database**: PostgreSQL for persistent storage
- **Cache**: Redis for caching and rate limiting
- **Background Jobs**: Celery for async task processing
- **AI Service**: OpenAI integration for content analysis

### Key Endpoints
- Health Check: `GET /api/v1/monitoring/health`
- Detailed Health: `GET /api/v1/monitoring/health/detailed`
- Metrics: `GET /api/v1/monitoring/metrics`
- User Protection: `/api/v1/social-protection/user/*`
- Bot Integration: `/api/v1/social-protection/bot/*`
- Extension: `/api/v1/social-protection/extension/*`
- Crisis Management: `/api/v1/social-protection/crisis/*`

## Monitoring and Health Checks

### System Health Monitoring

#### Check Overall System Health
```bash
curl -X GET https://api.linkshield.com/api/v1/monitoring/health
```

Expected Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-03T12:00:00Z",
  "services": {
    "database": {"healthy": true, "status": "healthy"},
    "redis": {"healthy": true, "status": "healthy"},
    "ai_service": {"healthy": true, "status": "healthy"}
  }
}
```

#### Check Detailed Health (Admin Only)
```bash
curl -X GET https://api.linkshield.com/api/v1/monitoring/health/detailed \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

#### Trigger Manual Health Check
```bash
curl -X POST https://api.linkshield.com/api/v1/monitoring/check \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Metrics Collection

#### View All Metrics
```bash
curl -X GET https://api.linkshield.com/api/v1/monitoring/metrics \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

#### View Specific Metric
```bash
curl -X GET "https://api.linkshield.com/api/v1/monitoring/metrics?metric_name=request_count&window_minutes=60" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Prometheus Metrics

Access Prometheus metrics at: `http://localhost:8000/metrics`

Key metrics to monitor:
- `social_protection_requests_total` - Total API requests
- `social_protection_request_duration_seconds` - Request latency
- `analyzer_execution_duration_seconds` - Analyzer performance
- `crisis_alerts_total` - Crisis alerts generated
- `cache_hits_total` / `cache_misses_total` - Cache performance

### Log Monitoring

Logs are structured JSON format. Key log locations:
- Application logs: `/var/log/linkshield/app.log`
- Error logs: `/var/log/linkshield/error.log`
- Access logs: `/var/log/linkshield/access.log`

#### Search for Errors
```bash
grep -i "error" /var/log/linkshield/app.log | tail -n 50
```

#### Monitor Real-time Logs
```bash
tail -f /var/log/linkshield/app.log | jq '.'
```

#### Filter by Operation
```bash
grep "operation.*analyze_content" /var/log/linkshield/app.log | jq '.'
```

## Common Operations

### Database Operations

#### Check Database Connection
```bash
psql -h localhost -U linkshield_user -d linkshield_db -c "SELECT 1;"
```

#### View Active Scans
```sql
SELECT id, user_id, platform, status, created_at 
FROM sp_social_profile_scans 
WHERE status IN ('pending', 'running') 
ORDER BY created_at DESC 
LIMIT 20;
```

#### View Recent Crisis Alerts
```sql
SELECT id, brand, severity, score, created_at 
FROM sp_crisis_alerts 
WHERE resolved = false 
ORDER BY created_at DESC 
LIMIT 10;
```

#### Check Database Size
```sql
SELECT 
  pg_size_pretty(pg_database_size('linkshield_db')) as db_size,
  pg_size_pretty(pg_total_relation_size('sp_social_profile_scans')) as scans_size,
  pg_size_pretty(pg_total_relation_size('sp_content_risk_assessments')) as assessments_size;
```

### Redis Operations

#### Check Redis Connection
```bash
redis-cli ping
```

#### View Cache Statistics
```bash
redis-cli INFO stats
```

#### Clear Specific Cache
```bash
redis-cli DEL "sp:analysis:*"
```

#### Monitor Redis Commands
```bash
redis-cli MONITOR
```

### Celery Background Jobs

#### Check Celery Workers
```bash
celery -A src.social_protection.tasks inspect active
```

#### View Task Queue Status
```bash
celery -A src.social_protection.tasks inspect stats
```

#### Purge Task Queue
```bash
celery -A src.social_protection.tasks purge
```

#### Restart Celery Workers
```bash
systemctl restart celery-worker
```

### Application Management

#### Check Application Status
```bash
systemctl status linkshield-api
```

#### Restart Application
```bash
systemctl restart linkshield-api
```

#### View Application Logs
```bash
journalctl -u linkshield-api -f
```

#### Reload Configuration
```bash
systemctl reload linkshield-api
```

## Troubleshooting

### High Error Rate

**Symptoms**: Error rate > 5% for 5+ minutes

**Diagnosis**:
1. Check health endpoint: `GET /api/v1/monitoring/health`
2. Review error logs: `grep ERROR /var/log/linkshield/error.log | tail -n 100`
3. Check database connectivity
4. Check Redis connectivity
5. Check AI service availability

**Resolution**:
1. If database issue: Check connection pool, restart database if needed
2. If Redis issue: Restart Redis service
3. If AI service issue: Check API keys, rate limits
4. If application issue: Restart application service

### Slow Response Times

**Symptoms**: p95 latency > 2 seconds

**Diagnosis**:
1. Check metrics: `GET /api/v1/monitoring/metrics`
2. Check database query performance
3. Check cache hit rate
4. Check analyzer execution times

**Resolution**:
1. If low cache hit rate: Increase cache TTL, check cache service
2. If slow database: Check indexes, optimize queries
3. If slow analyzers: Check AI service latency, optimize analysis logic
4. Scale horizontally: Add more application instances

### Crisis Detection Not Working

**Symptoms**: No crisis alerts generated when expected

**Diagnosis**:
1. Check crisis detector health
2. Review crisis detection logs
3. Check reputation tracker data
4. Verify crisis detection configuration

**Resolution**:
1. Check crisis detection task queue
2. Verify brand monitoring is configured
3. Check threshold configuration
4. Manually trigger crisis detection: `queue_crisis_detection()`

### Platform Adapter Failures

**Symptoms**: Platform-specific scans failing

**Diagnosis**:
1. Check adapter health status
2. Verify API credentials
3. Check rate limits
4. Review adapter logs

**Resolution**:
1. Verify API keys are valid and not expired
2. Check rate limit status with platform
3. Implement retry logic if transient failure
4. Disable adapter if platform API is down

### Memory Issues

**Symptoms**: High memory usage, OOM errors

**Diagnosis**:
1. Check application memory usage: `ps aux | grep uvicorn`
2. Check cache size: `redis-cli INFO memory`
3. Review memory metrics

**Resolution**:
1. Restart application to clear memory
2. Reduce cache size limits
3. Optimize analyzer memory usage
4. Scale vertically: Increase server memory

### Database Connection Pool Exhausted

**Symptoms**: "Too many connections" errors

**Diagnosis**:
1. Check active connections: `SELECT count(*) FROM pg_stat_activity;`
2. Check connection pool configuration
3. Review long-running queries

**Resolution**:
1. Kill idle connections: `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle';`
2. Increase connection pool size
3. Optimize query performance
4. Add connection timeout configuration

## Incident Response

### Severity Levels

**P0 - Critical**: Complete service outage
- Response time: Immediate
- Escalation: Page on-call engineer

**P1 - High**: Major functionality impaired
- Response time: 15 minutes
- Escalation: Notify engineering team

**P2 - Medium**: Minor functionality impaired
- Response time: 1 hour
- Escalation: Create ticket

**P3 - Low**: Cosmetic issues
- Response time: Next business day
- Escalation: Add to backlog

### Incident Response Procedure

1. **Acknowledge**: Acknowledge the incident in monitoring system
2. **Assess**: Determine severity and impact
3. **Communicate**: Notify stakeholders
4. **Investigate**: Use troubleshooting guide to diagnose
5. **Mitigate**: Implement temporary fix if needed
6. **Resolve**: Implement permanent fix
7. **Document**: Create incident report
8. **Review**: Conduct post-mortem

### Rollback Procedure

If deployment causes issues:

1. **Stop Traffic**: Put application in maintenance mode
2. **Rollback Code**: Deploy previous version
3. **Rollback Database**: Revert migrations if needed
4. **Verify**: Check health endpoints
5. **Resume Traffic**: Remove maintenance mode
6. **Monitor**: Watch metrics closely

```bash
# Rollback application
git checkout <previous-version-tag>
docker-compose up -d --build

# Rollback database migration
alembic downgrade -1

# Verify health
curl http://localhost:8000/api/v1/monitoring/health
```

## Maintenance Procedures

### Database Maintenance

#### Vacuum Database
```bash
psql -h localhost -U linkshield_user -d linkshield_db -c "VACUUM ANALYZE;"
```

#### Reindex Tables
```bash
psql -h localhost -U linkshield_user -d linkshield_db -c "REINDEX DATABASE linkshield_db;"
```

#### Backup Database
```bash
pg_dump -h localhost -U linkshield_user linkshield_db > backup_$(date +%Y%m%d).sql
```

#### Restore Database
```bash
psql -h localhost -U linkshield_user -d linkshield_db < backup_20251003.sql
```

### Cache Maintenance

#### Clear All Caches
```bash
redis-cli FLUSHALL
```

#### Clear Expired Keys
```bash
redis-cli --scan --pattern "sp:*" | xargs redis-cli DEL
```

### Log Rotation

Logs are automatically rotated by logrotate. Manual rotation:

```bash
logrotate -f /etc/logrotate.d/linkshield
```

### Certificate Renewal

SSL certificates auto-renew via Let's Encrypt. Manual renewal:

```bash
certbot renew --force-renewal
systemctl reload nginx
```

## Emergency Contacts

### On-Call Rotation
- Primary: [On-call engineer via PagerDuty]
- Secondary: [Backup engineer]
- Manager: [Engineering manager]

### External Services
- **AWS Support**: [AWS support portal]
- **OpenAI Support**: [OpenAI support email]
- **Database Support**: [Database vendor support]

### Escalation Path
1. On-call engineer (immediate)
2. Engineering manager (15 minutes)
3. CTO (30 minutes)
4. CEO (1 hour for P0 incidents)

## Useful Commands Reference

### Quick Health Check
```bash
# All-in-one health check
curl -s http://localhost:8000/api/v1/monitoring/health | jq '.'
```

### View Recent Errors
```bash
# Last 50 errors
grep ERROR /var/log/linkshield/app.log | tail -n 50 | jq '.'
```

### Check Service Status
```bash
# All services
systemctl status linkshield-api redis postgresql celery-worker
```

### Database Quick Stats
```sql
-- Active scans
SELECT status, COUNT(*) FROM sp_social_profile_scans GROUP BY status;

-- Crisis alerts by severity
SELECT severity, COUNT(*) FROM sp_crisis_alerts WHERE resolved = false GROUP BY severity;

-- Recent assessments
SELECT COUNT(*) FROM sp_content_risk_assessments WHERE created_at > NOW() - INTERVAL '1 hour';
```

### Performance Check
```bash
# API response time
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/api/v1/monitoring/health

# Database connections
psql -c "SELECT count(*) as connections FROM pg_stat_activity;"

# Redis memory
redis-cli INFO memory | grep used_memory_human
```

## Appendix

### Configuration Files
- Application: `/etc/linkshield/config.yaml`
- Nginx: `/etc/nginx/sites-available/linkshield`
- Systemd: `/etc/systemd/system/linkshield-api.service`
- Celery: `/etc/systemd/system/celery-worker.service`

### Environment Variables
- `LINKSHIELD_DATABASE_URL`: Database connection string
- `LINKSHIELD_REDIS_URL`: Redis connection string
- `LINKSHIELD_OPENAI_API_KEY`: OpenAI API key
- `LINKSHIELD_ENVIRONMENT`: Environment (development/staging/production)

### Monitoring Dashboards
- Grafana: `https://grafana.linkshield.com`
- Prometheus: `https://prometheus.linkshield.com`
- Sentry: `https://sentry.io/linkshield`

### Documentation Links
- API Documentation: `https://api.linkshield.com/docs`
- Architecture Docs: `docs/architecture.md`
- Deployment Guide: `docs/deployment.md`
- Security Guide: `docs/security.md`

---

**Last Updated**: 2025-10-03
**Version**: 1.0.0
**Maintained By**: LinkShield Engineering Team
