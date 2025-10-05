# Content Security Policy (CSP) Implementation

## Overview

LinkShield implements a robust Content Security Policy using nonce-based script and style loading to prevent XSS attacks while maintaining functionality.

## CSP Configuration

### Production Environment
- **Strict CSP**: No `unsafe-inline` or `unsafe-eval` allowed
- **Nonce-based**: All inline scripts and styles must use generated nonces
- **HTTPS enforcement**: `upgrade-insecure-requests` directive enabled
- **Report-Only**: Duplicate CSP header for monitoring violations

### Development Environment
- **Permissive CSP**: Allows `unsafe-eval` for development tools
- **Local connections**: Permits localhost and WebSocket connections
- **Inline styles**: Limited `unsafe-inline` for development convenience

## Using CSP Nonces in Templates

### Basic Usage

```python
from fastapi import Request
from src.security import get_csp_nonce, create_nonce_script_tag

def render_template(request: Request):
    nonce = get_csp_nonce(request)
    
    # Manual nonce usage
    script_html = f'<script nonce="{nonce}">console.log("Hello");</script>'
    
    # Using utility functions
    script_html = create_nonce_script_tag(request, 'console.log("Hello");')
```

### Context Manager Approach

```python
from src.security import CSPNonceContext

def render_complex_template(request: Request):
    with CSPNonceContext(request) as csp:
        script_tag = csp.script('console.log("Hello");')
        style_tag = csp.style('body { margin: 0; }')
        
        return f"""
        <html>
        <head>{style_tag}</head>
        <body>
            <h1>Hello World</h1>
            {script_tag}
        </body>
        </html>
        """
```

### Template Integration

For Jinja2 templates, make CSP utilities available:

```python
from fastapi.templating import Jinja2Templates
from src.security import get_csp_nonce

templates = Jinja2Templates(directory="templates")

# Add CSP function to template globals
templates.env.globals['get_csp_nonce'] = get_csp_nonce
```

Then in templates:

```html
<!-- template.html -->
<script nonce="{{ get_csp_nonce(request) }}">
    console.log("CSP-compliant script");
</script>

<style nonce="{{ get_csp_nonce(request) }}">
    .csp-safe { color: blue; }
</style>
```

## CSP Directives Explained

### Script Sources (`script-src`)
- `'self'`: Allow scripts from same origin
- `'nonce-{nonce}'`: Allow inline scripts with matching nonce
- `'unsafe-eval'`: Allow `eval()` (development only)

### Style Sources (`style-src`)
- `'self'`: Allow stylesheets from same origin
- `'nonce-{nonce}'`: Allow inline styles with matching nonce
- `'unsafe-inline'`: Allow inline styles (development only)

### Other Directives
- `default-src 'self'`: Default policy for all resource types
- `img-src 'self' data: https:`: Allow images from self, data URLs, and HTTPS
- `connect-src 'self'`: Allow AJAX/fetch to same origin
- `object-src 'none'`: Block all plugins (Flash, etc.)
- `base-uri 'self'`: Restrict `<base>` tag URLs
- `form-action 'self'`: Restrict form submission targets
- `frame-ancestors 'none'`: Prevent embedding in frames
- `upgrade-insecure-requests`: Force HTTPS for all resources

## CSP Violation Monitoring

### Report-Only Header
In production, a duplicate CSP header with `-Report-Only` suffix is sent to monitor violations without blocking content.

### Violation Reports
Configure CSP violation reporting:

```python
# Add to CSP policy
csp_policy += "report-uri /api/security/csp-report; "
```

### Handling Violations
Create an endpoint to receive CSP violation reports:

```python
@app.post("/api/security/csp-report")
async def csp_violation_report(request: Request):
    report = await request.json()
    logger.warning(f"CSP Violation: {report}")
    # Store violation for analysis
```

## Best Practices

### 1. Nonce Generation
- Use cryptographically secure random nonces
- Generate new nonce for each request
- Minimum 128-bit entropy (16 bytes base64-encoded)

### 2. Template Security
- Always use nonce for inline scripts/styles
- Avoid inline event handlers (`onclick`, etc.)
- Use external files when possible

### 3. Third-Party Resources
- Whitelist specific domains in CSP
- Use SRI (Subresource Integrity) for external resources
- Prefer self-hosted resources

### 4. Development vs Production
- Use stricter policies in production
- Test CSP changes in report-only mode first
- Monitor violation reports regularly

## Common Issues and Solutions

### Issue: Scripts Not Loading
**Cause**: Missing or incorrect nonce
**Solution**: Ensure all inline scripts use the request nonce

```python
# Wrong
script = '<script>alert("hello");</script>'

# Correct
nonce = get_csp_nonce(request)
script = f'<script nonce="{nonce}">alert("hello");</script>'
```

### Issue: External Resources Blocked
**Cause**: CSP doesn't allow external domains
**Solution**: Add trusted domains to CSP policy

```python
# Update CSP to allow specific domains
csp_policy = (
    f"script-src 'self' 'nonce-{nonce}' https://trusted-cdn.com; "
    f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com; "
)
```

### Issue: Development Tools Not Working
**Cause**: Strict CSP blocks development features
**Solution**: Use development-specific CSP with `unsafe-eval`

## Security Benefits

1. **XSS Prevention**: Blocks unauthorized script execution
2. **Data Exfiltration Protection**: Limits connection targets
3. **Clickjacking Prevention**: Prevents iframe embedding
4. **Mixed Content Protection**: Forces HTTPS usage
5. **Plugin Security**: Blocks dangerous plugins

## Performance Considerations

- Nonce generation adds minimal overhead (~1ms per request)
- CSP headers are small (~500 bytes)
- Browser CSP parsing is highly optimized
- No impact on static resource loading

## Testing CSP

### Browser Developer Tools
1. Open DevTools → Console
2. Look for CSP violation messages
3. Check Network tab for blocked resources

### Automated Testing
```python
def test_csp_headers(client):
    response = client.get("/")
    assert "Content-Security-Policy" in response.headers
    assert "nonce-" in response.headers["Content-Security-Policy"]
```

### CSP Validator Tools
- Use online CSP validators
- Test with CSP Evaluator
- Monitor real-world violations