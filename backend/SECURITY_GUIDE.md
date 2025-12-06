# Backend Security Guide

This document outlines all the security measures implemented in the Spacedly backend application.

## Security Measures Implemented

### 1. **Rate Limiting**

Protection against brute force attacks and DDoS attacks through tiered rate limiters:

- **Global API Limiter**: 100 requests per 15 minutes per IP
- **Authentication Limiter**: 5 login/register attempts per 15 minutes per IP
- **OTP Verification Limiter**: 5 attempts per 15 minutes per IP
- **Password Reset Limiter**: 3 attempts per hour per IP
- **File Upload Limiter**: 10 uploads per hour per IP

**Location**: `src/middlewares/security.middleware.ts`

### 2. **Security Headers (Helmet)**

Comprehensive HTTP security headers:

- **Content Security Policy (CSP)**: Prevents XSS attacks
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **Strict-Transport-Security (HSTS)**: Enforces HTTPS
- **X-XSS-Protection**: Browser XSS protection
- **Referrer-Policy**: Controls referrer information

**Configuration**: `helmetConfig` in `src/middlewares/security.middleware.ts`

### 3. **CORS (Cross-Origin Resource Sharing)**

Enhanced CORS configuration:

- Environment-based allowed origins
- Credentials support for authenticated requests
- Specific HTTP methods allowed (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- Controlled headers exposure

**Environment Variables**:
- `ALLOWED_ORIGINS`: Comma-separated list of allowed origins
- `FRONTEND_URL`: Default frontend URL

**Location**: `src/app.ts`

### 4. **Input Sanitization & XSS Protection**

Multiple layers of input protection:

- **MongoDB Injection Protection**: Using `express-mongo-sanitize`
- **XSS Attack Prevention**: Custom sanitization middleware removes dangerous scripts
- **HTTP Parameter Pollution (HPP)**: Protects against duplicate parameters

**Features**:
- Removes `<script>` and `<iframe>` tags
- Removes `javascript:` protocols
- Removes inline event handlers
- Whitelisted query parameters for legitimate use

**Location**: `src/middlewares/security.middleware.ts`

### 5. **Cookie Security**

Enhanced cookie security with environment-aware configuration:

**Development**:
- `httpOnly`: true (prevents JavaScript access)
- `secure`: false (allows HTTP)
- `sameSite`: 'lax' (CSRF protection)

**Production**:
- `httpOnly`: true
- `secure`: true (HTTPS only)
- `sameSite`: 'strict' (stronger CSRF protection)
- `domain`: Configurable via `COOKIE_DOMAIN` env variable

**Token Lifetimes**:
- Access Token: 15 minutes
- Refresh Token: 7 days

**Location**: `src/utils/cookieUtil.ts`

### 6. **Request Body Size Limits**

Protection against DoS attacks through large payloads:

- JSON body limit: 10MB
- URL-encoded body limit: 10MB

**Location**: `src/app.ts`

### 7. **Request Timeout**

Prevents resource exhaustion from long-running requests:

- Default timeout: 30 seconds
- Returns 408 (Request Timeout) if exceeded

**Location**: `src/middlewares/security.middleware.ts`

### 8. **File Upload Security**

Protected file upload with multiple validations:

- **Rate Limiting**: 10 uploads per hour
- **File Type Validation**: Only allowed extensions (images, PDFs, documents)
- **File Size Limit**: 10MB maximum
- **MIME Type Checking**: Validates both extension and MIME type
- **Unique Filenames**: Prevents file overwriting

**Allowed File Types**:
- Images: jpeg, jpg, png, gif
- Documents: pdf, doc, docx, txt, xls, xlsx, ppt, pptx

**Location**: `src/middlewares/upload.middleware.ts`

### 9. **Authentication & Authorization**

Secure authentication flow:

- **JWT Tokens**: Separate access and refresh tokens
- **Token Rotation**: New access token generated on expiry
- **Token Validation**: Verified on every protected request
- **Refresh Token Storage**: Stored in database for validation
- **Two-Factor Authentication (2FA)**: Optional OTP-based 2FA

### 10. **Password Security**

- **Hashing**: bcrypt with salt rounds
- **Minimum Length**: 6 characters (configurable via validation)
- **Password Reset**: Token-based with expiration
- **Rate Limited**: Reset requests limited to 3 per hour

## Environment Configuration

### Required Environment Variables

```env
# Security Configuration
ALLOWED_ORIGINS=http://localhost:5173,https://yourdomain.com
COOKIE_DOMAIN=.yourdomain.com
NODE_ENV=production

# JWT Secrets (use strong random strings)
JWT_ACCESS_SECRET=your_strong_secret_here
JWT_REFRESH_SECRET=your_strong_secret_here
```

### Production Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Configure `ALLOWED_ORIGINS` with your production domains
- [ ] Set `COOKIE_DOMAIN` for your domain
- [ ] Use strong, unique JWT secrets
- [ ] Enable HTTPS/SSL on your server
- [ ] Configure firewall rules
- [ ] Enable database encryption
- [ ] Regular security audits
- [ ] Keep dependencies updated

## Security Best Practices

### 1. **Keep Dependencies Updated**

```bash
npm audit
npm audit fix
```

### 2. **Monitor Rate Limit Violations**

Check logs for suspicious activity:
- Multiple 429 (Too Many Requests) responses
- Failed authentication attempts
- Unusual API usage patterns

### 3. **Regular Security Testing**

- SQL injection testing
- XSS vulnerability scanning
- CSRF testing
- Authentication bypass attempts
- Rate limit testing

### 4. **Database Security**

- Use parameterized queries (Sequelize ORM handles this)
- Implement least privilege access
- Regular backups
- Encrypt sensitive data at rest

### 5. **Logging & Monitoring**

- Log security events (failed logins, rate limit hits)
- Monitor error rates
- Set up alerts for anomalies
- Regular log analysis

## Testing Security Features

### Test Rate Limiting

```bash
# Test login rate limit (should block after 5 attempts)
for i in {1..10}; do
  curl -X POST http://localhost:5000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}'
done
```

### Test CORS

```bash
# Test with allowed origin
curl -X OPTIONS http://localhost:5000/api/auth/login \
  -H "Origin: http://localhost:5173" \
  -H "Access-Control-Request-Method: POST"

# Test with disallowed origin (should fail)
curl -X OPTIONS http://localhost:5000/api/auth/login \
  -H "Origin: http://malicious-site.com" \
  -H "Access-Control-Request-Method: POST"
```

### Test Input Sanitization

```bash
# Test XSS protection
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"<script>alert(1)</script>","email":"test@test.com","password":"password123"}'
```

## Security Headers Verification

After deploying, verify security headers using:

1. **securityheaders.com**: Online header scanner
2. **Mozilla Observatory**: Comprehensive security audit
3. **Browser DevTools**: Check response headers

Expected headers:
- `Strict-Transport-Security`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy`
- `X-XSS-Protection`

## Incident Response

In case of a security incident:

1. **Immediate Actions**:
   - Rotate all JWT secrets
   - Invalidate all active sessions
   - Review logs for breach scope
   - Notify affected users

2. **Investigation**:
   - Analyze attack vectors
   - Check for data exfiltration
   - Review access logs

3. **Recovery**:
   - Patch vulnerabilities
   - Update security measures
   - Document incident
   - Implement additional monitoring

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Helmet.js Documentation](https://helmetjs.github.io/)
- [OWASP API Security](https://owasp.org/www-project-api-security/)

## Support

For security concerns or to report vulnerabilities, contact the development team immediately.

**Last Updated**: December 2025
