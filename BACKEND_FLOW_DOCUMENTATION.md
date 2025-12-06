# Spacedly Backend - Complete Flow Documentation
### Interview Preparation Guide for Node.js Developer

---

## Table of Contents

1. [Application Architecture Overview](#1-application-architecture-overview)
2. [Authentication & Authorization System](#2-authentication--authorization-system)
3. [Security Middleware Layer](#3-security-middleware-layer)
4. [Task Management System](#4-task-management-system)
5. [File Upload & Management](#5-file-upload--management)
6. [Reminder & Notification System](#6-reminder--notification-system)
7. [Analytics & Reporting](#7-analytics--reporting)
8. [Database Schema & Associations](#8-database-schema--associations)
9. [Common Interview Questions](#9-common-interview-questions)

---

## 1. Application Architecture Overview

### Tech Stack
- **Runtime**: Node.js with TypeScript
- **Framework**: Express.js
- **Database**: PostgreSQL with Sequelize ORM
- **Authentication**: JWT (Access + Refresh Tokens), Passport.js (Google OAuth)
- **File Storage**: Cloudinary
- **Image Processing**: Sharp
- **Email**: Nodemailer
- **Caching**: NodeCache (In-memory)
- **Scheduling**: node-cron
- **Security**: Helmet, express-rate-limit, hpp

### Project Structure
```
backend/
├── src/
│   ├── app.ts              # Express app configuration
│   ├── server.ts           # Server entry point
│   ├── constants.ts        # HTTP status codes
│   ├── config/             # Database, Cloudinary, Passport configs
│   ├── controllers/        # Request handlers
│   ├── services/           # Business logic
│   ├── routes/             # API routes
│   ├── middlewares/        # Auth, Security, Upload middlewares
│   ├── models/             # Sequelize models
│   ├── validations/        # Joi schemas
│   ├── helpers/            # Auth helpers, Email templates, OTP
│   ├── utils/              # Error handlers, Async wrapper, Response
│   └── migrations/         # Database migrations
```

### Request Flow Architecture
```
Frontend (React)
    ↓
API Endpoint (/api/...)
    ↓
Security Middlewares (Helmet, CORS, Rate Limiting, Input Sanitization)
    ↓
Route Handler
    ↓
Authentication Middleware (if protected route)
    ↓
Validation Middleware (Joi schemas)
    ↓
Controller (Request handler)
    ↓
Service Layer (Business logic)
    ↓
Database (Sequelize ORM)
    ↓
Response (Success/Error)
    ↓
Frontend
```

---

## 2. Authentication & Authorization System

### 2.1 User Registration Flow (Local)

#### **Complete Flow Diagram**
```
User fills registration form (Frontend)
    ↓
POST /api/auth/register
    ↓
[Security Middlewares]
- Helmet (Security headers)
- CORS (Cross-origin verification)
- Rate Limiter (5 requests per 15 min)
- Input Sanitization (XSS, NoSQL injection prevention)
    ↓
[Route Handler] auth.routes.ts
    ↓
[Controller] registerUser()
    ↓
[Validation] Joi Schema Validation
- name: required, string, min 2 chars
- email: required, valid email format
- password: required, min 6 chars, strong password pattern
    ↓
[Service] userRegister()
    ↓
[Check] User already exists?
- Query: SELECT * FROM users WHERE email = ?
- If exists → throw ApiError (400, "User already exists")
    ↓
[Hash Password]
- Using bcrypt with salt rounds = 10
- hashPassword = bcrypt.hash(password, 10)
    ↓
[Database] Create User
- INSERT INTO users (name, email, password, auth_provider)
- VALUES (name, email, hashedPassword, 'local')
    ↓
[Response] 201 Created
- Return user data (id, name, email)
- Exclude password from response
    ↓
User receives success message
```

#### **Code Breakdown**

**1. Route Definition** (`auth.routes.ts`)
```typescript
router.post('/register', authLimiter, registerUser);
```
- Rate limited to 5 attempts per 15 minutes
- Prevents brute force attacks

**2. Controller** (`user.controller.ts`)
```typescript
export const registerUser = asyncWrapper(async (req: Request, res: Response) => {
  const { name, email, password } = req.body;
  
  // Validate input
  await createUserSchema.validateAsync({ name, email, password });
  
  // Call service
  const user = await userRegister({ name, email, password });
  
  // Return response
  return ApiResponse.created(res, { user }, 'User registered successfully');
});
```

**3. Service Layer** (`user.service.ts`)
```typescript
export const userRegister = async ({ name, email, password }) => {
  // Check if user exists
  const existingUser = await User.findOne({ where: { email } });
  if (existingUser) {
    throw new ApiError(400, 'User already exists');
  }
  
  // Hash password
  const hashpassword = await hashPassword(password);
  
  // Create user
  const user = await User.create({ 
    name, 
    email, 
    password: hashpassword,
    auth_provider: 'local'
  });
  
  return { id: user.id, name: user.name, email: user.email };
};
```

**4. Password Hashing** (`helpers/auth.ts`)
```typescript
export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};
```

#### **Interview Questions**

**Q1: Why do we hash passwords before storing them?**
**A:** Password hashing is crucial for security. Even if the database is compromised, attackers cannot retrieve plaintext passwords. We use bcrypt which:
- Adds salt (random data) to prevent rainbow table attacks
- Is computationally expensive to slow down brute force attacks
- Uses adaptive hashing (can increase rounds as hardware improves)

**Q2: What is the difference between hashing and encryption?**
**A:**
- **Hashing**: One-way function, cannot be reversed. Used for passwords.
- **Encryption**: Two-way function, can be decrypted with a key. Used for sensitive data that needs to be retrieved.

**Q3: Why use Joi for validation instead of manual checks?**
**A:**
- Declarative schema definition
- Comprehensive validation rules
- Better error messages
- Type safety with TypeScript
- Reduces code complexity
- Industry standard

**Q4: What is the purpose of asyncWrapper?**
**A:** It's a higher-order function that wraps async route handlers to catch errors and pass them to error handling middleware, eliminating the need for try-catch blocks in every controller.

**Q5: How would you implement email verification on registration?**
**A:**
1. Generate verification token on registration
2. Store token and expiry in database
3. Send email with verification link
4. User clicks link → verify token
5. Mark email as verified
6. Require verified email for certain features

**Q6: What is the purpose of the auth_provider field?**
**A:** Tracks how user registered ('local', 'google'). Allows:
- Different login flows based on provider
- Preventing password login for OAuth users without set password
- Analytics on registration methods
- Multi-provider account linking

**Q7: How do you handle user account deletion?**
**A:** Soft vs Hard delete:
- **Soft delete**: Set `deleted_at` timestamp, keep data
- **Hard delete**: CASCADE delete all related data
- Consider: GDPR compliance, data retention policies
- Anonymize data instead of deletion for analytics

---

### 2.2 Login Flow (with Optional 2FA)

#### **Complete Flow Diagram**
```
User submits login form
    ↓
POST /api/auth/login
    ↓
[Security Middlewares]
- Rate Limiter (5 attempts per 15 min)
- Input Sanitization
    ↓
[Controller] loginUser()
    ↓
[Validation] Joi Schema
- email: required, valid email
- password: required, string
    ↓
[Service] initiateTwoFactorAuth()
    ↓
[Database Query] Find user by email
- SELECT * FROM users WHERE email = ?
    ↓
[Check] User exists?
    ↓ No
    Return error (401, "Invalid credentials")
    ↓ Yes
[Check] Is 2FA enabled?
    ↓ Yes (2FA enabled)
    Generate 6-digit OTP
    ↓
    Store OTP in database
    - UPDATE users SET two_factor_otp = ?, 
      two_factor_otp_expiry = NOW() + 5 minutes
    ↓
    Send OTP via email (Nodemailer)
    ↓
    Return success (200, "OTP sent to email")
    ↓
    User enters OTP on frontend
    ↓
    POST /api/auth/verify-otp
    ↓
    [Controller] verifyOtp()
    ↓
    [Validation] Check OTP & expiry
    ↓
    [Generate Tokens] (proceed to token generation)
    
    ↓ No (2FA disabled)
    [Service] userLogin()
    ↓
    [Verify Password]
    - bcrypt.compare(inputPassword, hashedPassword)
    ↓
    Invalid → 401 error
    Valid ↓
    [Generate JWT Tokens]
    - Access Token (15 min expiry)
    - Refresh Token (7 day expiry)
    ↓
    [Store Refresh Token in DB]
    - UPDATE users SET refresh_token = ? WHERE id = ?
    ↓
    [Set HTTP-Only Cookies]
    - accessToken cookie (15 min)
    - refreshToken cookie (7 days)
    ↓
    [Response] 200 Success
    - Return user data + success message
    ↓
    Frontend stores user in Redux state
```

#### **Code Breakdown**

**1. Controller** (`user.controller.ts`)
```typescript
export const loginUser = asyncWrapper(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  
  // Validate
  await loginUserSchema.validateAsync({ email, password });
  
  // Check 2FA
  const user = await initiateTwoFactorAuth(email);
  
  if (user.is_two_factor_enabled) {
    // Generate OTP
    const otp = generateOTP(); // 6-digit random number
    user.two_factor_otp = otp;
    user.two_factor_otp_expiry = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();
    
    // Send email
    await sendEmail(email, 'Your Login OTP', otpTemplate(otp));
    
    return ApiResponse.success(res, {}, 'OTP sent to your email');
  }
  
  // Regular login
  const { accessToken, refreshToken, user_data } = await userLogin({ email, password });
  
  // Set cookies
  setAuthCookies(res, accessToken, refreshToken);
  
  return ApiResponse.success(res, { user: user_data }, 'Login successful');
});
```

**2. Service Layer** (`user.service.ts`)
```typescript
export const userLogin = async ({ email, password }) => {
  const user = await User.findOne({ where: { email } });
  
  if (!user) {
    throw new ApiError(401, 'Invalid credentials');
  }
  
  // Check if OAuth user without password
  if (user.auth_provider !== 'local' && !user.password) {
    throw new ApiError(400, 
      `This account is linked with ${user.auth_provider}. Please use ${user.auth_provider} to login`
    );
  }
  
  // Verify password
  if (!user.password || !(await comparePassword(password, user.password))) {
    throw new ApiError(401, 'Invalid credentials');
  }
  
  // Generate tokens
  const accessToken = generateAccessToken(user.id, user.email);
  const refreshToken = generateRefreshToken(user.id, user.email);
  
  // Save refresh token
  user.refresh_token = refreshToken;
  await user.save();
  
  return {
    accessToken,
    refreshToken,
    user_data: {
      id: user.id,
      name: user.name,
      email: user.email,
      is_two_factor_enabled: user.is_two_factor_enabled
    }
  };
};
```

**3. JWT Token Generation** (`helpers/auth.ts`)
```typescript
export const generateAccessToken = (id: string, email: string): string => {
  return jwt.sign(
    { id, email },
    process.env.JWT_ACCESS_SECRET!,
    { expiresIn: '15m' }
  );
};

export const generateRefreshToken = (id: string, email: string): string => {
  return jwt.sign(
    { id, email },
    process.env.JWT_REFRESH_SECRET!,
    { expiresIn: '7d' }
  );
};
```

**4. Cookie Setting** (`utils/cookieUtil.ts`)
```typescript
export const setAuthCookies = (res: Response, accessToken: string, refreshToken: string) => {
  // Access token cookie
  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 15 * 60 * 1000 // 15 minutes
  });
  
  // Refresh token cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
};
```

#### **Interview Questions**

**Q1: What is JWT and how does it work?**
**A:** JWT (JSON Web Token) is a compact, self-contained way to securely transmit information between parties as a JSON object. It consists of:
- **Header**: Algorithm and token type
- **Payload**: Claims (user data)
- **Signature**: Ensures token hasn't been tampered with

Benefits:
- Stateless authentication
- No server-side session storage needed
- Can be verified without database lookup
- Works well for microservices

**Q2: Why use both Access and Refresh tokens?**
**A:**
- **Access Token**: Short-lived (15 min), sent with every request, reduces attack window if compromised
- **Refresh Token**: Long-lived (7 days), used only to get new access tokens, stored in database for validation

This provides security (short-lived access) + convenience (don't need to login frequently).

**Q3: What is the purpose of httpOnly cookies?**
**A:** HttpOnly cookies cannot be accessed via JavaScript (document.cookie), preventing XSS attacks. They're automatically sent with requests, providing security while maintaining convenience.

**Q4: Explain the 2FA flow in detail.**
**A:** 
1. User submits credentials
2. System verifies credentials
3. If 2FA enabled, generate random 6-digit OTP
4. Store OTP in database with 5-minute expiry
5. Send OTP via email
6. User receives OTP and submits it
7. System validates OTP and expiry
8. If valid, generate tokens and login
9. Clear OTP from database

Benefits: Adds second layer of security even if password is compromised.

**Q5: What is the difference between authentication and authorization?**
**A:**
- **Authentication**: Verifying who you are (login with credentials)
- **Authorization**: Verifying what you can access (permissions/roles)

Example: Authentication proves you're user123, authorization checks if user123 can delete tasks.

**Q6: How would you implement "Remember Me" functionality?**
**A:**
1. Extend refresh token expiry (30 days instead of 7)
2. Store "remember" flag in token payload
3. Use different cookie maxAge based on flag
4. Security: Use device fingerprinting
5. Allow users to revoke remembered devices

**Q7: What is token hijacking and how to prevent it?**
**A:** Attacker steals valid token and uses it.

Prevention:
- Short-lived access tokens
- Refresh token rotation
- IP address validation
- Device fingerprinting
- Monitor for unusual activity
- Logout all sessions on password change

**Q8: Explain the OTP generation and validation process.**
**A:**
1. Generate 6-digit random number (100000-999999)
2. Store in database with 5-minute expiry
3. Send via email
4. User submits OTP
5. Validate: correct OTP + not expired
6. Clear OTP from database after validation
7. Rate limit OTP attempts (5 per 15 min)

**Q9: How would you handle concurrent login sessions?**
**A:** Options:
1. **Allow multiple sessions**: Different refresh tokens per device
2. **Single session**: Invalidate old token on new login
3. **Limit sessions**: Max 3-5 active devices
4. **Device management**: Let user view/revoke sessions

Implementation: Store array of refresh tokens with device info

---

### 2.3 JWT Authentication Middleware

#### **Complete Flow Diagram**
```
Protected API Request
    ↓
[Auth Middleware] Execution
    ↓
Extract cookies from request
- accessToken
- refreshToken
    ↓
[Check] Both tokens missing?
    ↓ Yes
    Return 401 Unauthorized
    ↓ No
[Verify Access Token]
- jwt.verify(accessToken, JWT_ACCESS_SECRET)
    ↓
[Access Token Valid?]
    ↓ Yes
    Decode token → Extract user ID & email
    ↓
    Attach user to request object
    req.user = { id, email }
    ↓
    Call next() → Continue to controller
    
    ↓ No/Expired
    [Check] Refresh token exists?
        ↓ No
        Return 401 Unauthorized
        ↓ Yes
    [Verify Refresh Token]
    - jwt.verify(refreshToken, JWT_REFRESH_SECRET)
        ↓
    [Refresh Token Invalid?]
        ↓ Yes
        Return 401 Unauthorized
        ↓ No (Valid)
    [Database Query] Verify refresh token
    - SELECT * FROM users WHERE id = ? AND refresh_token = ?
        ↓
    [Token doesn't match DB?]
        ↓ Yes
        Return 401 Unauthorized (possible token theft)
        ↓ No (Match)
    [Generate New Access Token]
    - newAccessToken = generateAccessToken(user.id, user.email)
        ↓
    [Set New Cookie]
    - res.cookie('accessToken', newAccessToken, ...)
        ↓
    Attach user to request
    req.user = { id, email }
        ↓
    Call next() → Continue to controller
```

#### **Code Breakdown**

**Middleware Implementation** (`middlewares/auth.middleware.ts`)
```typescript
export const authMiddleware = async (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const { accessToken, refreshToken } = req.cookies;
    
    // Step 1: Check if tokens exist
    if (!accessToken && !refreshToken) {
      return unauthorized(res);
    }
    
    // Step 2: Verify access token
    if (accessToken) {
      try {
        const decodedAccess = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET!);
        
        if (decodedAccess) {
          req.user = { 
            id: decodedAccess.id, 
            email: decodedAccess.email 
          };
          return next(); // Access token valid → proceed
        }
      } catch {
        // Access token invalid/expired → try refresh token
      }
    }
    
    // Step 3: No refresh token available
    if (!refreshToken) {
      return unauthorized(res);
    }
    
    // Step 4: Verify refresh token
    let decodedRefresh;
    try {
      decodedRefresh = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!);
    } catch {
      return unauthorized(res);
    }
    
    // Step 5: Check user exists and token matches DB
    const user = await User.findByPk(decodedRefresh.id);
    if (!user || user.refresh_token !== refreshToken) {
      return unauthorized(res);
    }
    
    // Step 6: Generate new access token
    const newAccessToken = generateAccessToken(user.id, user.email);
    
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });
    
    // Step 7: Attach user and continue
    req.user = { id: user.id, email: user.email };
    next();
    
  } catch (err) {
    return unauthorized(res);
  }
};
```

#### **Interview Questions**

**Q1: Why verify refresh token against database?**
**A:** 
- Allows immediate token revocation (logout invalidates token)
- Detects token theft (if someone steals refresh token, we can invalidate it)
- Provides audit trail
- Enables "logout all sessions" functionality

**Q2: What happens if both tokens are expired?**
**A:** User gets 401 Unauthorized and must login again. This is by design - refresh tokens eventually expire for security.

**Q3: How does token rotation work in this system?**
**A:** When access token expires, we use refresh token to generate a new access token. The refresh token itself doesn't rotate in every request but only at login. More advanced systems rotate refresh tokens too.

**Q4: What is the security benefit of short-lived access tokens?**
**A:**
- Limits damage window if token is stolen
- Forces regular re-validation
- Reduces risk of replay attacks
- Balances security with user experience

**Q5: How do you prevent token reuse attacks?**
**A:** Token reuse: Using same token multiple times after it's invalidated.

Prevention:
- One-time refresh tokens (rotate on each use)
- Blacklist invalidated tokens (Redis)
- JTI (JWT ID) claim for tracking
- Detect multiple simultaneous uses
- Automatic session termination on suspicious activity

**Q6: What is the difference between symmetric and asymmetric JWT signing?**
**A:**
- **Symmetric (HS256)**: Same secret for signing and verifying
  - Faster, simpler
  - Secret must be kept on all servers
  - Used in our application
  
- **Asymmetric (RS256)**: Private key signs, public key verifies
  - More secure for distributed systems
  - Public key can be shared
  - Slower performance

**Q7: How would you implement multi-factor authentication beyond 2FA?**
**A:**
- **Something you know**: Password
- **Something you have**: Phone (OTP), Hardware token
- **Something you are**: Biometrics (fingerprint, face)
- **Somewhere you are**: Location-based
- **Something you do**: Behavioral patterns

Combine 2+ factors for stronger security.

---

### 2.4 Google OAuth Flow

#### **Complete Flow Diagram**
```
User clicks "Login with Google"
    ↓
Frontend redirects to: GET /api/auth/google
    ↓
[Passport.js Middleware] Initiates OAuth
    ↓
Redirect to Google Login Page
    ↓
User logs in with Google credentials
    ↓
Google redirects to callback: GET /api/auth/google/callback
    ↓
[Passport.js] Receives authorization code
    ↓
[Passport.js] Exchanges code for access token
    ↓
[Passport.js] Fetches user profile from Google
    ↓
[Passport Strategy Callback] Custom logic
    ↓
Extract email from Google profile
    ↓
[Database Query] User exists with google_id?
    ↓ Yes
    Return existing user
    
    ↓ No
    [Database Query] User exists with email?
        ↓ Yes (Local account with same email)
        Link Google account to existing user
        - UPDATE users SET google_id = ?, auth_provider = 'google'
        
        ↓ No (Completely new user)
        Create new user
        - INSERT INTO users (name, email, google_id, auth_provider, password)
        - VALUES (googleName, googleEmail, googleId, 'google', NULL)
    ↓
[Controller] googleAuthCallback()
    ↓
[Generate JWT Tokens]
- accessToken = generateAccessToken(user.id, user.email)
- refreshToken = generateRefreshToken(user.id, user.email)
    ↓
[Save Refresh Token to DB]
- UPDATE users SET refresh_token = ? WHERE id = ?
    ↓
[Set HTTP-Only Cookies]
- accessToken (15 min)
- refreshToken (7 days)
    ↓
[Redirect to Frontend Dashboard]
- res.redirect(`${FRONTEND_URL}/dashboard`)
    ↓
Frontend receives cookies automatically
    ↓
User is logged in
```

#### **Code Breakdown**

**1. Passport Configuration** (`config/passport.ts`)
```typescript
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: '/api/auth/google/callback'
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        
        if (!email) {
          return done(new Error('No email from Google'), null);
        }
        
        // Check if user exists with Google ID
        let user = await User.findOne({ where: { google_id: profile.id } });
        
        if (!user) {
          // Check if email exists (local account)
          user = await User.findOne({ where: { email } });
          
          if (user) {
            // Link Google to existing account
            user.google_id = profile.id;
            user.auth_provider = 'google';
            user.name = profile.displayName || user.name;
            await user.save();
          } else {
            // Create new user
            user = await User.create({
              name: profile.displayName || 'Google User',
              email,
              google_id: profile.id,
              auth_provider: 'google',
              password: null,
              is_two_factor_enabled: false
            });
          }
        }
        
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);
```

**2. Route Definitions** (`routes/auth.routes.ts`)
```typescript
// Initiate OAuth flow
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false
  })
);

// OAuth callback
router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=google_auth_failed`,
    session: false
  }),
  googleAuthCallback
);
```

**3. Callback Controller** (`controllers/user.controller.ts`)
```typescript
export const googleAuthCallback = asyncWrapper(
  async (req: Request, res: Response) => {
    const user = req.user as User;
    
    if (!user) {
      return res.redirect(`${FRONTEND_URL}/login?error=user_not_found`);
    }
    
    // Generate tokens
    const accessToken = generateAccessToken(user.id, user.email);
    const refreshToken = generateRefreshToken(user.id, user.email);
    
    // Save refresh token
    user.refresh_token = refreshToken;
    await user.save();
    
    // Set cookies
    setAuthCookies(res, accessToken, refreshToken);
    
    // Redirect to dashboard
    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  }
);
```

#### **Interview Questions**

**Q1: What is OAuth 2.0 and how does it work?**
**A:** OAuth 2.0 is an authorization framework that allows third-party applications to access user data without exposing credentials. Flow:
1. User clicks "Login with Google"
2. Redirected to Google's authorization server
3. User grants permission
4. Google redirects back with authorization code
5. App exchanges code for access token
6. App uses token to fetch user data from Google

**Q2: Why use Passport.js for OAuth?**
**A:**
- Abstracts complex OAuth flows
- Supports 500+ authentication strategies
- Well-maintained and widely used
- Handles state validation, CSRF protection
- Simplifies integration with multiple providers

**Q3: How do you handle users who sign up with both email and Google?**
**A:** We link accounts by email:
- If Google email matches existing local account, we add google_id to that account
- User can then login with either method
- Prevents duplicate accounts with same email

**Q4: What security considerations are important for OAuth?**
**A:**
- Validate redirect URIs (prevent open redirects)
- Use state parameter (CSRF protection)
- Store secrets securely (environment variables)
- Use HTTPS in production
- Validate token signatures
- Handle token expiration properly

**Q5: What is the state parameter in OAuth and why is it important?**
**A:** State parameter prevents CSRF attacks in OAuth flow:
1. Generate random string before redirect
2. Store in session/cookie
3. Include in OAuth request as `state` parameter
4. Google returns same `state` in callback
5. Verify returned state matches stored value
6. If mismatch → potential CSRF attack, reject

**Q6: How do you handle OAuth token refresh?**
**A:**
1. Store Google refresh token (long-lived)
2. Use to get new access tokens when expired
3. Update user data periodically
4. Handle revocation (user disconnects app)
5. Re-authenticate if refresh token expires

**Q7: What is the difference between OAuth and OpenID Connect?**
**A:**
- **OAuth 2.0**: Authorization framework (access to resources)
- **OpenID Connect**: Authentication layer on top of OAuth
  - Adds ID token (JWT with user info)
  - Standardized user info endpoint
  - Used by Google, Facebook, etc.

We use OpenID Connect via Passport.js.

---

### 2.5 Password Reset Flow

#### **Complete Flow Diagram**
```
User clicks "Forgot Password"
    ↓
POST /api/auth/forgot-password
    ↓
[Security] Rate Limiter (3 attempts per hour)
    ↓
[Controller] forgotPassword()
    ↓
[Validation] Joi schema (email format)
    ↓
[Service] forgotPasswordService(email)
    ↓
[Database Query] Find user by email
    ↓
[User Not Found?]
    ↓ Yes
    Return generic success (security: don't reveal if email exists)
    "If email exists, reset link sent"
    
    ↓ No (User found)
[Generate Reset Token]
- crypto.randomBytes(32).toString('hex')
- Generates secure random token (e.g., "a7b8c9d0e1f2...")
    ↓
[Hash Token]
- hashedToken = crypto.createHash('sha256').update(token).digest('hex')
- Store hashed version in DB (security: if DB compromised, token still safe)
    ↓
[Database Update]
- UPDATE users SET
    reset_password_token = hashedToken,
    reset_password_expires = NOW() + 1 hour
  WHERE id = user.id
    ↓
[Send Email]
- Create reset URL: `${FRONTEND_URL}/reset-password?token=${plainToken}`
- Send email with reset link
- Email contains plaintext token (needed for verification)
    ↓
Return success message
"Reset link sent to email"
    ↓
User receives email, clicks reset link
    ↓
Frontend opens: /reset-password?token=a7b8c9d0e1f2...
    ↓
User enters new password
    ↓
POST /api/auth/reset-password
Body: { token, password }
    ↓
[Security] Rate Limiter (3 attempts per hour)
    ↓
[Controller] resetPassword()
    ↓
[Validation] Joi schema
- token: required, string
- password: required, min 6 chars, strong pattern
    ↓
[Service] resetPasswordService(token, newPassword)
    ↓
[Hash Token] (same way as before)
- hashedToken = crypto.createHash('sha256').update(token).digest('hex')
    ↓
[Database Query]
- SELECT * FROM users WHERE reset_password_token = hashedToken
    ↓
[Token Not Found?]
    ↓ Yes
    Return error (400, "Invalid or expired token")
    
    ↓ No (Token found)
[Check Expiry]
- if (NOW() > reset_password_expires)
    ↓ Expired
    Return error (400, "Token has expired")
    
    ↓ Valid
[Hash New Password]
- newHashedPassword = bcrypt.hash(newPassword, 10)
    ↓
[Database Update]
- UPDATE users SET
    password = newHashedPassword,
    reset_password_token = NULL,
    reset_password_expires = NULL,
    refresh_token = NULL  (logout all sessions)
  WHERE id = user.id
    ↓
Return success
"Password reset successfully"
    ↓
User can login with new password
```

#### **Code Breakdown**

**1. Forgot Password Service** (`services/user.service.ts`)
```typescript
export const forgotPasswordService = async (email: string) => {
  const user = await User.findOne({ where: { email } });
  
  // Don't reveal if user exists (security)
  if (!user) {
    return {
      message: 'If email exists, reset link has been sent'
    };
  }
  
  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  // Hash token before saving
  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  // Set token and expiration
  user.reset_password_token = hashedToken;
  user.reset_password_expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  await user.save();
  
  return {
    resetToken, // Return unhashed token for email
    user
  };
};
```

**2. Reset Password Service** (`services/user.service.ts`)
```typescript
export const resetPasswordService = async (token: string, newPassword: string) => {
  // Hash the provided token
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  
  // Find user with this token
  const user = await User.findOne({
    where: { reset_password_token: hashedToken }
  });
  
  if (!user) {
    throw new ApiError(400, 'Invalid or expired reset token');
  }
  
  // Check expiration
  if (new Date() > new Date(user.reset_password_expires!)) {
    throw new ApiError(400, 'Reset token has expired');
  }
  
  // Hash new password
  const hashedPassword = await hashPassword(newPassword);
  
  // Update password and clear reset fields
  user.password = hashedPassword;
  user.reset_password_token = null;
  user.reset_password_expires = null;
  user.refresh_token = null; // Logout all sessions
  await user.save();
  
  return { message: 'Password reset successfully' };
};
```

**3. Email Template** (`helpers/emailTemplates.ts`)
```typescript
export const passwordResetTemplate = (resetUrl: string, userName: string) => {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2>Password Reset Request</h2>
      <p>Hi ${userName},</p>
      <p>We received a request to reset your password. Click the button below:</p>
      <a href="${resetUrl}" 
         style="background: #007bff; color: white; padding: 10px 20px; 
                text-decoration: none; border-radius: 5px;">
        Reset Password
      </a>
      <p>This link expires in 1 hour.</p>
      <p>If you didn't request this, ignore this email.</p>
    </div>
  `;
};
```

#### **Interview Questions**

**Q1: Why hash the reset token before storing in database?**
**A:** Defense in depth:
- If database is compromised, attacker can't use tokens
- Even with DB access, they need the plaintext token from email
- Adds extra security layer
- Similar to password hashing principle

**Q2: Why return generic message even if email doesn't exist?**
**A:** Security through obscurity:
- Prevents user enumeration attacks
- Attackers can't probe which emails are registered
- Protects user privacy
- Industry best practice

**Q3: Why invalidate refresh tokens on password reset?**
**A:** Security measure:
- If account was compromised, this logs out all sessions
- User must login again with new password
- Prevents attacker from maintaining access
- Ensures clean security state

**Q4: What is the difference between crypto and bcrypt?**
**A:**
- **crypto**: Node.js built-in, for hashing tokens/data, faster, deterministic
- **bcrypt**: For passwords, adaptive (can increase cost), includes salt, specifically designed for password storage

**Q5: How would you prevent brute force attacks on reset tokens?**
**A:** Multiple layers:
- Rate limiting (3 attempts per hour)
- Token expiration (1 hour)
- Cryptographically secure random tokens (very long)
- Hash tokens in database
- Email notification of password changes

**Q6: What is the difference between password reset and password change?**
**A:**
- **Password Reset**: User forgot password, needs email verification
  - Requires email address
  - Sends reset link
  - No current password needed
  - Use case: Forgotten password
  
- **Password Change**: User knows current password
  - Requires current password
  - Directly updates password
  - No email needed
  - Use case: Regular security update

**Q7: How do you handle password reset for OAuth users?**
**A:**
1. Check if user has password set
2. If no password: "Set password" flow instead of reset
3. If has password: Normal reset flow
4. Consider: Should OAuth users be able to set passwords?
5. Our approach: Allow setting password for backup login method

**Q8: What is a timing attack and how to prevent it in password verification?**
**A:** Timing attack: Measuring response time to determine if email exists.

Prevention:
- Always return same generic message
- Add random delay (50-200ms)
- Use constant-time comparison
- Hash lookups even for non-existent users

Example:
```typescript
// Bad: Returns different messages
if (!user) return "Email not found"
if (!validPassword) return "Invalid password"

// Good: Generic message
if (!user || !validPassword) return "Invalid credentials"
```

---

## 3. Security Middleware Layer

### 3.1 Security Middleware Stack

#### **Complete Middleware Flow**
```
Incoming HTTP Request
    ↓
[1] Trust Proxy Configuration
- app.set('trust proxy', 1)
- Trusts first proxy for correct client IP
- Important for rate limiting behind load balancer
    ↓
[2] Helmet - Security Headers
- Content Security Policy (CSP)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict-Transport-Security (HSTS)
- X-XSS-Protection
    ↓
[3] Request Timeout (30 seconds)
- Prevents slow-loris attacks
- Aborts requests taking > 30s
    ↓
[4] CORS (Cross-Origin Resource Sharing)
- Validates origin against whitelist
- Sets Access-Control headers
- Handles preflight requests
    ↓
[5] Body Parser
- JSON limit: 10MB (prevents DoS)
- URL-encoded limit: 10MB
    ↓
[6] Cookie Parser
- Parses cookies from request
    ↓
[7] HPP (HTTP Parameter Pollution)
- Prevents duplicate parameter attacks
- Whitelist: [sort, fields, page, limit, status, priority, category]
    ↓
[8] Input Sanitization
- XSS protection (removes script tags)
- NoSQL injection prevention (removes $ operators)
    ↓
[9] Route-Specific Rate Limiting
/api/auth/login → 5 requests / 15 min
/api/auth/register → 5 requests / 15 min
/api/auth/forgot-password → 3 requests / hour
/api/auth/verify-otp → 5 requests / 15 min
/api → 100 requests / 15 min (global)
    ↓
[10] Static File Serving
- /uploads directory
    ↓
[11] Passport Initialization
- OAuth middleware
    ↓
[12] Route Handlers
- /api routes
    ↓
[13] 404 Handler (Route Not Found)
    ↓
[14] Global Error Handler
    ↓
Response sent to client
```

#### **Code Breakdown**

**1. Helmet Configuration** (`middlewares/security.middleware.ts`)
```typescript
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
});
```

**Purpose of Each CSP Directive:**
- `defaultSrc`: Fallback for other directives
- `scriptSrc`: Controls JavaScript sources (prevents inline scripts)
- `imgSrc`: Controls image sources
- `connectSrc`: Controls AJAX, WebSocket connections
- `frameSrc: none`: Prevents clickjacking

**2. CORS Configuration** (`app.ts`)
```typescript
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : [process.env.FRONTEND_URL || 'http://localhost:8080'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Set-Cookie'],
  maxAge: 600 // Cache preflight for 10 minutes
}));
```

**3. Rate Limiting** (`middlewares/security.middleware.ts`)
```typescript
// Global API rate limiter
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many requests. Try again after 15 minutes.'
    });
  }
});

// Authentication rate limiter
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true // Only count failed attempts
});

// Password reset rate limiter
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3
});

// OTP verification rate limiter
export const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true
});

// File upload rate limiter
export const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10
});
```

**4. Input Sanitization** (`middlewares/security.middleware.ts`)
```typescript
export const sanitizeInput = (req, res, next) => {
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  
  if (req.params) {
    const sanitizedParams = sanitizeObject(req.params);
    Object.defineProperty(req, 'params', {
      value: sanitizedParams,
      writable: true,
      configurable: true
    });
  }
  
  if (req.query) {
    const sanitizedQuery = sanitizeObject(req.query);
    Object.defineProperty(req, 'query', {
      value: sanitizedQuery,
      writable: true,
      configurable: true
    });
  }
  
  next();
};

function sanitizeValue(value: any): any {
  if (typeof value === 'string') {
    // NoSQL injection protection
    if (value.startsWith('$') || value.includes('$where')) {
      console.warn(`Blocked NoSQL injection: ${value.substring(0, 50)}`);
      return value.replace(/\$/g, '').replace(/\$where/gi, '');
    }
    
    // XSS protection
    return value
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .trim();
  }
  
  // Prevent object-based NoSQL injection
  if (typeof value === 'object' && value !== null) {
    const keys = Object.keys(value);
    const hasDangerousKeys = keys.some(key => key.startsWith('$'));
    
    if (hasDangerousKeys) {
      console.warn('Blocked object with MongoDB operators');
      const sanitized = {};
      keys.forEach(key => {
        if (!key.startsWith('$')) {
          sanitized[key] = value[key];
        }
      });
      return sanitized;
    }
  }
  
  return value;
}
```

#### **Interview Questions**

**Q1: What is CSP (Content Security Policy) and why is it important?**
**A:** CSP is a security header that prevents XSS attacks by controlling which resources can be loaded. Benefits:
- Prevents inline script execution
- Blocks unauthorized external resources
- Mitigates clickjacking
- Reduces attack surface
Example: `scriptSrc: ["'self'"]` only allows scripts from same origin

**Q2: Explain CORS and why it's necessary.**
**A:** CORS (Cross-Origin Resource Sharing) is a security feature that controls which domains can access your API. Without CORS:
- Any website could make requests to your API
- Could lead to CSRF attacks
- User credentials could be stolen

Our implementation:
- Whitelist allowed origins
- Allow credentials (cookies)
- Specify allowed methods and headers

**Q3: Why use different rate limiters for different routes?**
**A:** Different routes have different risk profiles:
- **Auth routes (5/15min)**: High risk, brute force attacks
- **Password reset (3/hour)**: Prevent enumeration, abuse
- **Upload (10/hour)**: Prevent DoS via large files
- **Global (100/15min)**: General API abuse prevention

**Q4: What is HTTP Parameter Pollution (HPP)?**
**A:** Attack where duplicate parameters are sent to confuse server:
```
?status=pending&status=completed&status[$ne]=null
```
HPP middleware prevents this by keeping only the first/last value for non-whitelisted parameters.

**Q5: How does input sanitization prevent NoSQL injection?**
**A:** NoSQL injection uses MongoDB operators in queries:
```javascript
// Malicious input
{ "email": { "$ne": null } }  // Returns all users

// After sanitization
{ "email": "ne: null" }  // Harmless string
```
We remove `$` characters and `$where` operators from input.

**Q6: What is the purpose of `skipSuccessfulRequests: true`?**
**A:** Only counts failed attempts toward rate limit. Example:
- User fails login 4 times → counter = 4
- User succeeds on 5th try → counter resets
- Prevents legitimate users from being locked out
- Still stops brute force (many failures = blocked)

**Q7: How does Helmet's CSP prevent XSS attacks?**
**A:** CSP defines trusted sources for content:
```javascript
scriptSrc: ["'self'"]  // Only allow scripts from same origin
```
If attacker injects: `<script src="evil.com/hack.js">`
Browser blocks it because evil.com not in whitelist.

Also prevents inline scripts (`<script>alert('xss')</script>`)

**Q8: What is the difference between XSS and CSRF?**
**A:**
- **XSS (Cross-Site Scripting)**: Inject malicious scripts
  - Executes in victim's browser
  - Steals cookies, session tokens
  - Prevention: Input sanitization, CSP
  
- **CSRF (Cross-Site Request Forgery)**: Force authenticated user to make unwanted requests
  - Example: Click link that transfers money
  - Uses user's active session
  - Prevention: CSRF tokens, SameSite cookies

**Q9: Explain the trust proxy setting.**
**A:** When behind reverse proxy (Nginx, load balancer):
```javascript
app.set('trust proxy', 1)
```
Trusts `X-Forwarded-For` header for client IP.

Without it: All requests appear from proxy IP (wrong for rate limiting)
With it: Gets real client IP from header

Security: Only trust first proxy, not arbitrary headers.

**Q10: How do you prevent timing attacks in rate limiting?**
**A:** Rate limiting can reveal information through response times:
- Fast response: Not rate limited
- Slow response: Rate limited

Mitigation:
- Constant-time responses
- Same error format
- Don't reveal remaining attempts
- Use sliding window algorithm

---

### 3.2 Error Handling

#### **Error Handling Flow**
```
Error occurs anywhere in application
    ↓
[Is it ApiError?]
    ↓ Yes
    Custom error with status code + message
    ↓
[Global Error Handler] errorHandler()
    ↓
[Check Error Type]
    ↓
[ApiError] (custom errors)
- Extract status code and message
- Log error
- Send JSON response

[Sequelize Validation Error]
- Extract validation errors
- Format as array
- Send 400 Bad Request

[JWT Errors]
- TokenExpiredError → 401 "Token expired"
- JsonWebTokenError → 401 "Invalid token"

[Multer Errors]
- File size exceeded → 400 "File too large"
- Invalid file type → 400 "Invalid file type"

[Unknown Errors]
- Log full error
- Send 500 "Internal Server Error"
- Hide error details in production
    ↓
Response sent to client
```

#### **Code Implementation**

**1. Custom ApiError Class** (`utils/apiError.ts`)
```typescript
class ApiError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true; // Distinguish from programming errors
    Error.captureStackTrace(this, this.constructor);
  }
}

export default ApiError;
```

**2. Global Error Handler** (`middlewares/errorHandler.ts`)
```typescript
export const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Default to 500 if no status code
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';

  // Log error (in production, use proper logging service)
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    statusCode
  });

  // Sequelize validation errors
  if (err.name === 'SequelizeValidationError') {
    statusCode = 400;
    message = err.errors.map((e: any) => e.message).join(', ');
  }

  // Sequelize unique constraint violation
  if (err.name === 'SequelizeUniqueConstraintError') {
    statusCode = 400;
    message = 'Duplicate entry found';
  }

  // JWT errors
  if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token has expired';
  }

  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
  }

  // Joi validation errors
  if (err.isJoi) {
    statusCode = 400;
    message = err.details.map((d: any) => d.message).join(', ');
  }

  // Multer errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    statusCode = 400;
    message = 'File size too large. Maximum 10MB allowed.';
  }

  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    statusCode = 400;
    message = 'Too many files uploaded';
  }

  // Send error response
  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack 
    })
  });
};

export const routeNotFound = (req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
};
```

**3. AsyncWrapper Utility** (`utils/asyncWrapper.ts`)
```typescript
const asyncWrapper = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

export default asyncWrapper;
```

**Usage:**
```typescript
export const createTask = asyncWrapper(async (req, res) => {
  // If any error occurs, automatically caught and passed to error handler
  const task = await taskService.createTask(req.body);
  return ApiResponse.success(res, { task }, 'Task created');
});
```

#### **Interview Questions**

**Q1: What is the difference between operational and programming errors?**
**A:**
- **Operational Errors**: Expected errors (user input, network issues, DB down)
  - Should be handled gracefully
  - Example: "User not found", "Invalid password"
  
- **Programming Errors**: Bugs in code (undefined variable, syntax error)
  - Should crash and restart (in production with PM2/Kubernetes)
  - Example: TypeError, ReferenceError

Our `isOperational` flag helps distinguish these.

**Q2: Why use asyncWrapper instead of try-catch in every function?**
**A:**
- DRY principle (Don't Repeat Yourself)
- Cleaner code
- Consistent error handling
- Reduces boilerplate
- Automatically passes errors to error middleware

**Q3: How would you implement error logging in production?**
**A:** Use dedicated logging services:
- **Winston**: Structured logging with multiple transports
- **Sentry**: Error tracking with stack traces, user context
- **CloudWatch/DataDog**: Cloud-based monitoring

Should log:
- Error message and stack trace
- Request context (URL, method, user ID)
- Timestamp
- Environment details

**Q4: Why hide error details in production?**
**A:** Security reasons:
- Stack traces reveal code structure
- Error messages might expose sensitive data
- Could help attackers understand vulnerabilities
- Better to log internally, show generic message to users

**Q5: What is the difference between 4xx and 5xx errors?**
**A:**
- **4xx (Client errors)**: Problem with request
  - 400: Bad Request (invalid input)
  - 401: Unauthorized (not logged in)
  - 403: Forbidden (no permission)
  - 404: Not Found
  - 429: Too Many Requests
  
- **5xx (Server errors)**: Problem with server
  - 500: Internal Server Error
  - 502: Bad Gateway
  - 503: Service Unavailable
  - 504: Gateway Timeout

Client can retry 5xx, shouldn't retry 4xx.

**Q6: How do you handle uncaught exceptions in Node.js?**
**A:**
```typescript
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Log to monitoring service
  // Graceful shutdown
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
  // Log to monitoring service
});
```
Production: Use PM2/Docker to auto-restart.

**Q7: What is circuit breaker pattern and when to use it?**
**A:** Prevents cascading failures by stopping requests to failing service:

States:
1. **Closed**: Normal operation
2. **Open**: Too many failures, reject requests immediately
3. **Half-Open**: Test if service recovered

Example: If Cloudinary down, don't keep trying (timeout every request).
Instead: Fail fast, retry after cooldown period.

---

## 4. Task Management System

### 4.1 Create Task Flow

#### **Complete Flow Diagram**
```
User fills task form on frontend
- Title, description, dueDate, priority, category, status
    ↓
POST /api/tasks
Body: { title, description, dueDate, priority, category, status }
Headers: Cookie (accessToken, refreshToken)
    ↓
[Security Middlewares]
- Helmet, CORS, Rate Limiting, Input Sanitization
    ↓
[Auth Middleware]
- Verify JWT token
- Extract user ID from token
- Attach to req.user
    ↓
[Controller] createTask()
    ↓
[Validation] Joi Schema
- title: required, string, min 3, max 200 chars
- description: optional, string, max 1000 chars
- dueDate: required, valid ISO date
- priority: optional, enum ['low', 'medium', 'high']
- category: optional, string
- status: optional, enum ['todo', 'in-progress', 'completed']
    ↓
Validation fails → 400 Bad Request with error details
Validation passes ↓
    ↓
[Service] createTask()
    ↓
[Database Operation]
INSERT INTO tasks (
  user_id, title, description, due_date, 
  priority, category, status, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
    ↓
[Database Response] Created task with ID
    ↓
[Cache Invalidation]
- Delete cache key: `analytics:${userId}`
- Ensures analytics refresh on next request
    ↓
[Response] 201 Created
{
  success: true,
  data: { task: {...} },
  message: "Task created successfully"
}
    ↓
Frontend receives task
- Updates Redux state
- Adds task to UI list
- Shows success toast
```

#### **Code Breakdown**

**1. Route Definition** (`routes/task.routes.ts`)
```typescript
const router = express.Router();

// All task routes require authentication
router.use(authMiddleware);

router.post('/', taskController.createTask);
router.get('/', taskController.getTasks);
router.get('/:id', taskController.getTask);
router.put('/:id', taskController.updateTask);
router.delete('/:id', taskController.deleteTask);
```

**2. Controller** (`controllers/task.controller.ts`)
```typescript
export const createTask = asyncWrapper(
  async (req: CustomRequest, res: Response) => {
    const { id: userId } = req.user!; // From auth middleware
    const taskData = req.body;
    
    // Validate
    await createTaskSchema.validateAsync(taskData);
    
    // Create task
    const task = await taskService.createTask({
      userId: String(userId),
      ...taskData
    });
    
    return ApiResponse.created(
      res,
      { task },
      'Task created successfully'
    );
  }
);
```

**3. Validation Schema** (`validations/task.validation.ts`)
```typescript
export const createTaskSchema = Joi.object({
  title: Joi.string()
    .min(3)
    .max(200)
    .required()
    .messages({
      'string.empty': 'Title is required',
      'string.min': 'Title must be at least 3 characters',
      'string.max': 'Title cannot exceed 200 characters'
    }),
    
  description: Joi.string()
    .max(1000)
    .allow('')
    .optional(),
    
  dueDate: Joi.date()
    .iso()
    .required()
    .messages({
      'date.base': 'Due date must be a valid date',
      'any.required': 'Due date is required'
    }),
    
  priority: Joi.string()
    .valid('low', 'medium', 'high')
    .default('medium'),
    
  category: Joi.string()
    .max(50)
    .optional(),
    
  status: Joi.string()
    .valid('todo', 'in-progress', 'completed')
    .default('todo')
});
```

**4. Service Layer** (`services/task.service.ts`)
```typescript
export const createTask = async (data: {
  userId: string;
  title: string;
  description?: string;
  dueDate: Date;
  priority?: string;
  category?: string;
  status?: string;
}) => {
  const task = await Task.create({
    userId: data.userId,
    title: data.title,
    description: data.description,
    dueDate: data.dueDate,
    priority: data.priority || 'medium',
    category: data.category,
    status: data.status || 'todo'
  });
  
  // Invalidate analytics cache
  await cacheService.delPattern(`analytics:${data.userId}`);
  
  return task;
};
```

**5. Task Model** (`models/task.model.ts`)
```typescript
@Table({ tableName: 'tasks', timestamps: true })
class Task extends Model {
  @PrimaryKey
  @Default(DataType.UUIDV4)
  @Column(DataType.UUID)
  id!: string;

  @ForeignKey(() => User)
  @Column(DataType.UUID)
  userId!: string;

  @Column(DataType.STRING(200))
  title!: string;

  @Column(DataType.TEXT)
  description?: string;

  @Column(DataType.DATE)
  dueDate!: Date;

  @Default('medium')
  @Column(DataType.ENUM('low', 'medium', 'high'))
  priority!: string;

  @Column(DataType.STRING(50))
  category?: string;

  @Default('todo')
  @Column(DataType.ENUM('todo', 'in-progress', 'completed'))
  status!: string;

  @BelongsTo(() => User)
  user!: User;

  @HasMany(() => TaskAttachment)
  attachments!: TaskAttachment[];

  @HasMany(() => Reminder)
  reminders!: Reminder[];
}
```

#### **Interview Questions**

**Q1: Why separate controller and service layers?**
**A:** Separation of concerns:
- **Controller**: Handles HTTP (request/response, status codes, validation)
- **Service**: Business logic, database operations, reusable code

Benefits:
- Testability (can unit test service without HTTP)
- Reusability (service can be called from multiple controllers)
- Maintainability (clear responsibility boundaries)
- Clean architecture principles

**Q2: What is the purpose of UUIDs over auto-increment IDs?**
**A:**
- **Security**: Harder to guess, prevents enumeration
- **Distribution**: Can generate without DB, good for microservices
- **Merging**: No ID conflicts when merging databases
- **Privacy**: Doesn't reveal business metrics (user count, etc.)

**Q3: Why invalidate cache after creating a task?**
**A:** Cache coherence:
- Analytics depend on task data
- Creating task changes statistics
- Old cached data would be stale
- Pattern-based deletion (`analytics:${userId}`) ensures all related cache entries are cleared

**Q4: How does asyncWrapper prevent memory leaks?**
**A:** By properly catching promise rejections:
- Without wrapper, unhandled promise rejections can crash Node.js
- Wrapper ensures all async errors are caught and handled
- Prevents resource leaks from unclosed connections
- Maintains application stability

**Q5: What is database connection pooling and why use it?**
**A:** Connection pool maintains reusable database connections:

Benefits:
- Faster: Reuse existing connections vs creating new
- Resource efficient: Limit max connections
- Scalability: Handle concurrent requests
- Prevents: Too many connections error

Sequelize config:
```typescript
pool: {
  max: 10,     // Maximum connections
  min: 2,      // Minimum connections
  acquire: 30000,  // Max time to get connection
  idle: 10000   // Max idle time before release
}
```

**Q6: How do you handle database migrations in production?**
**A:**
1. **Zero-downtime migrations**: Make backward-compatible changes
2. **Version control**: Track migrations in Git
3. **Rollback plan**: Test rollback before deploying
4. **Backup**: Always backup before migration
5. **Staging**: Test on staging first
6. **Monitoring**: Watch for errors during migration
7. **Gradual**: Use feature flags for schema changes

**Q7: What is optimistic vs pessimistic locking?**
**A:**
- **Optimistic Locking**: Assume no conflicts
  - Use version number/timestamp
  - Check version before update
  - If changed → conflict error
  - Better for low contention
  
- **Pessimistic Locking**: Lock row during read
  - `SELECT ... FOR UPDATE`
  - Prevents concurrent modifications
  - Can cause deadlocks
  - Better for high contention

---

### 4.2 Get Tasks Flow (with Associations)

#### **Complete Flow Diagram**
```
User navigates to Tasks page
    ↓
GET /api/tasks
Headers: Cookie (accessToken, refreshToken)
    ↓
[Security Middlewares]
    ↓
[Auth Middleware]
- Extract userId from token
    ↓
[Controller] getTasks()
    ↓
[Service] getAllUserTasks(userId)
    ↓
[Database Query with Eager Loading]
SELECT 
  tasks.*,
  attachments.id, attachments.filename, attachments.url,
  reminders.id, reminders.scheduled_at, reminders.status
FROM tasks
LEFT JOIN task_attachments AS attachments ON tasks.id = attachments.task_id
LEFT JOIN reminders ON tasks.id = reminders.task_id
WHERE tasks.user_id = ?
ORDER BY tasks.due_date ASC
    ↓
[Sequelize Processes Associations]
- Groups attachments with each task
- Groups reminders with each task
- Returns nested objects
    ↓
[Response] 200 OK
{
  success: true,
  data: {
    tasks: [
      {
        id: "uuid-1",
        title: "Complete project",
        dueDate: "2024-12-10",
        priority: "high",
        status: "in-progress",
        attachments: [
          { id: "att-1", filename: "design.pdf", url: "cloudinary-url" }
        ],
        reminders: [
          { id: "rem-1", scheduledAt: "2024-12-09T09:00:00Z", status: "pending" }
        ]
      },
      ...
    ]
  }
}
    ↓
Frontend renders tasks with attachments and reminders
```

#### **Code Breakdown**

**Service with Associations** (`services/task.service.ts`)
```typescript
export const getAllUserTasks = async (userId: string) => {
  const tasks = await Task.findAll({
    where: { userId },
    include: [
      {
        model: TaskAttachment,
        as: 'attachments',
        attributes: ['id', 'filename', 'fileUrl', 'fileType', 'fileSize']
      },
      {
        model: Reminder,
        as: 'reminders',
        attributes: ['id', 'scheduledAt', 'status', 'type']
      }
    ],
    order: [['dueDate', 'ASC']]
  });
  
  return tasks;
};
```

**Model Associations** (`models/associations.ts`)
```typescript
// User has many Tasks
User.hasMany(Task, {
  foreignKey: 'userId',
  as: 'tasks',
  onDelete: 'CASCADE'
});

Task.belongsTo(User, {
  foreignKey: 'userId',
  as: 'user'
});

// Task has many Attachments
Task.hasMany(TaskAttachment, {
  foreignKey: 'taskId',
  as: 'attachments',
  onDelete: 'CASCADE'
});

TaskAttachment.belongsTo(Task, {
  foreignKey: 'taskId',
  as: 'task'
});

// Task has many Reminders
Task.hasMany(Reminder, {
  foreignKey: 'taskId',
  as: 'reminders',
  onDelete: 'CASCADE'
});

Reminder.belongsTo(Task, {
  foreignKey: 'taskId',
  as: 'task'
});
```

#### **Interview Questions**

**Q1: What is the N+1 query problem and how do we solve it?**
**A:** 
**Problem**: Without eager loading:
```typescript
// 1 query to get tasks
const tasks = await Task.findAll({ where: { userId } });

// N queries to get attachments (1 per task)
for (let task of tasks) {
  task.attachments = await TaskAttachment.findAll({ where: { taskId: task.id } });
}
// Total: 1 + N queries
```

**Solution**: Eager loading with `include`:
```typescript
// Single query with JOINs
const tasks = await Task.findAll({
  where: { userId },
  include: ['attachments', 'reminders']
});
// Total: 1 query
```

**Q2: What does `onDelete: 'CASCADE'` mean?**
**A:** Database-level referential integrity:
- When a task is deleted, all related attachments and reminders are automatically deleted
- Prevents orphaned records
- Ensures data consistency
- Can be handled at:
  - Database level (CASCADE constraint)
  - ORM level (Sequelize hooks)
  - Application level (manual deletion)

**Q3: What is the difference between `belongsTo` and `hasMany`?**
**A:**
- **belongsTo**: The model has the foreign key
  - `Task.belongsTo(User)` → tasks table has `userId` column
  
- **hasMany**: The related model has the foreign key
  - `User.hasMany(Task)` → tasks table has `userId` column

Relationship is defined from both sides for bidirectional access.

---

### 4.3 Update Task Flow

#### **Complete Flow Diagram**
```
User edits task on frontend
    ↓
PUT /api/tasks/:id
Body: { status: 'completed' }
    ↓
[Auth Middleware]
    ↓
[Controller] updateTask()
    ↓
[Validation] updateTaskSchema
- All fields optional
- Same rules as create
    ↓
[Service] updateTask(taskId, userId, updateData)
    ↓
[Database Query] Find task
SELECT * FROM tasks WHERE id = ? AND user_id = ?
    ↓
[Task not found or not owned by user]
    ↓ 
    throw ApiError(404, "Task not found")
    
[Task found] ↓
[Update Task]
UPDATE tasks 
SET status = ?, updated_at = NOW()
WHERE id = ? AND user_id = ?
    ↓
[Cache Invalidation]
- Delete analytics cache
    ↓
[Create Notification] (if status changed to completed)
INSERT INTO notifications (
  user_id, type, title, message, related_task_id
) VALUES (?, 'general', 'Task Completed', 'You completed: ...', ?)
    ↓
[Response] 200 OK
{
  success: true,
  data: { task: {...updated task...} },
  message: "Task updated successfully"
}
```

#### **Code Implementation**

```typescript
export const updateTask = async (
  taskId: string,
  userId: string,
  updateData: any
) => {
  // Find task
  const task = await Task.findOne({
    where: { id: taskId, userId }
  });
  
  if (!task) {
    throw new ApiError(404, 'Task not found');
  }
  
  // Track if status changed to completed
  const wasCompleted = task.status !== 'completed' && 
                       updateData.status === 'completed';
  
  // Update task
  await task.update(updateData);
  
  // Invalidate cache
  await cacheService.delPattern(`analytics:${userId}`);
  
  // Create notification if completed
  if (wasCompleted) {
    await notificationService.createNotification({
      userId,
      type: 'general',
      title: 'Task Completed',
      message: `You completed: ${task.title}`,
      relatedTaskId: task.id
    });
  }
  
  return task;
};
```

---

### 4.4 Delete Task Flow

#### **Complete Flow Diagram**
```
User clicks delete on task
    ↓
DELETE /api/tasks/:id
    ↓
[Auth Middleware]
    ↓
[Controller] deleteTask()
    ↓
[Service] deleteTask(taskId, userId)
    ↓
[Find Task]
SELECT * FROM tasks WHERE id = ? AND user_id = ?
    ↓
[Not found] → 404 error
    ↓
[Found] 
[CASCADE Delete] (handled by database)
DELETE FROM tasks WHERE id = ?
    ↓
[Database automatically deletes:]
- All task_attachments with task_id = ?
- All reminders with task_id = ?
- All notifications with related_task_id = ?
    ↓
[Delete Files from Cloudinary]
- Get all attachment URLs
- Loop through and delete from Cloudinary
- cloudinary.uploader.destroy(publicId)
    ↓
[Cache Invalidation]
    ↓
[Response] 200 OK
{
  success: true,
  message: "Task deleted successfully"
}
```

#### **Code Implementation**

```typescript
export const deleteTask = async (taskId: string, userId: string) => {
  const task = await Task.findOne({
    where: { id: taskId, userId },
    include: [{ model: TaskAttachment, as: 'attachments' }]
  });
  
  if (!task) {
    throw new ApiError(404, 'Task not found');
  }
  
  // Delete files from Cloudinary
  if (task.attachments && task.attachments.length > 0) {
    for (const attachment of task.attachments) {
      const publicId = attachment.fileUrl.split('/').pop()?.split('.')[0];
      if (publicId) {
        await cloudinary.uploader.destroy(`spacedly/attachments/${publicId}`);
      }
    }
  }
  
  // Delete task (cascade handles related records)
  await task.destroy();
  
  // Invalidate cache
  await cacheService.delPattern(`analytics:${userId}`);
  
  return { message: 'Task deleted successfully' };
};
```

#### **Interview Questions**

**Q1: Why check userId when deleting?**
**A:** Authorization and security:
- Prevents users from deleting others' tasks
- Even with valid task ID, user must own it
- Defense against parameter tampering
- Ensures data isolation in multi-tenant app

**Q2: Should file deletion be synchronous or asynchronous?**
**A:** Depends on requirements:

**Synchronous** (current implementation):
- Ensures files are deleted before response
- Transaction-like behavior
- User knows deletion is complete
- Could slow down response if many files

**Asynchronous** (alternative):
- Delete task immediately
- Queue file deletions for background job
- Faster response time
- Risk: Files remain if job fails
- Need retry mechanism

For small applications, synchronous is simpler and safer.

**Q3: What happens if Cloudinary deletion fails?**
**A:** Current implementation: Error is thrown, task isn't deleted

Better approach:
```typescript
try {
  await cloudinary.uploader.destroy(publicId);
} catch (error) {
  console.error('Cloudinary deletion failed:', error);
  // Continue with task deletion anyway
  // Log for manual cleanup
}
```

Or use a cleanup job that periodically checks for orphaned files.

---

## 5. File Upload & Management

### 5.1 File Upload Flow (with Image Optimization)

#### **Complete Flow Diagram**
```
User selects files to upload
    ↓
POST /api/tasks/:id/attachments
Content-Type: multipart/form-data
Files: [file1.jpg, file2.pdf, file3.png]
    ↓
[Security Middlewares]
    ↓
[Auth Middleware]
    ↓
[Upload Middleware] Multer
    ↓
[File Filter] Check file type
- Allowed: jpeg, jpg, png, gif, webp, pdf, doc, docx, txt, xls, xlsx, ppt, pptx
- Max size: 10MB per file
- Max files: 10 per request
    ↓
[Invalid file?] → 400 "Invalid file type"
[File too large?] → 400 "File too large"
    ↓
[Valid files] ↓
[Store in Memory] (Buffer)
- Not saved to disk yet
- Allows processing before upload
    ↓
[optimizeAndUpload Middleware]
    ↓
For each file:
    [Check if Image]
    - Check mimetype: image/jpeg, image/png, etc.
        ↓ Yes (Image file)
        [Sharp Optimization]
        1. Convert to optimal format (WebP for photos, PNG for graphics)
        2. Resize if larger than 1920x1080
        3. Compress with quality=70
        4. Strip metadata (EXIF)
            ↓
        Original: 5.2MB (3024x4032 JPEG)
        Optimized: 0.8MB (1920x1080 WebP)
        Compression: 85%
            ↓
        [Upload to Cloudinary]
        - Folder: spacedly/attachments
        - Public ID: filename-timestamp-random
        - Resource type: image
            ↓
        
        ↓ No (Non-image file like PDF)
        [Upload Directly to Cloudinary]
        - No optimization needed
        - Resource type: raw
            ↓
    [Cloudinary Response]
    - secure_url: https://res.cloudinary.com/...
    - public_id: spacedly/attachments/file-123
    - format: webp, pdf, etc.
        ↓
[All files uploaded] 
    ↓
[Controller] uploadAttachments()
    ↓
[Service] addTaskAttachments()
    ↓
[Verify Task Ownership]
SELECT * FROM tasks WHERE id = ? AND user_id = ?
    ↓
[Create Attachment Records]
INSERT INTO task_attachments (
  task_id, filename, file_url, file_type, file_size, public_id
) VALUES (?, ?, ?, ?, ?, ?)
    ↓
[Response] 200 OK
{
  success: true,
  data: {
    attachments: [
      {
        id: "uuid",
        filename: "image.jpg",
        fileUrl: "https://cloudinary-url",
        fileType: "image/webp",
        fileSize: 825344,
        optimizationStats: {
          originalSize: 5242880,
          optimizedSize: 825344,
          compressionRatio: 85
        }
      },
      ...
    ]
  },
  message: "Files uploaded successfully"
}
    ↓
Frontend displays uploaded files with optimization stats
```

#### **Code Breakdown**

**1. Upload Middleware** (`middlewares/upload.middleware.ts`)
```typescript
// File filter
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp|pdf|doc|docx|txt|xls|xlsx|ppt|pptx/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  
  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only images, PDFs, and documents allowed.'));
  }
};

// Multer configuration
export const upload = multer({
  storage: multer.memoryStorage(), // Store in memory for Sharp processing
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
  },
  fileFilter: fileFilter
});
```

**2. Image Optimization** (`utils/imageOptimizer.ts`)
```typescript
export const optimizeImage = async (
  buffer: Buffer,
  options: {
    quality?: number;
    maxWidth?: number;
    maxHeight?: number;
    format?: 'webp' | 'jpeg' | 'png';
  }
): Promise<Buffer> => {
  const { quality = 80, maxWidth = 1920, maxHeight = 1080, format = 'webp' } = options;
  
  let sharpInstance = sharp(buffer);
  
  // Get image metadata
  const metadata = await sharpInstance.metadata();
  
  // Resize if necessary
  if (metadata.width && metadata.width > maxWidth || 
      metadata.height && metadata.height > maxHeight) {
    sharpInstance = sharpInstance.resize(maxWidth, maxHeight, {
      fit: 'inside',
      withoutEnlargement: true
    });
  }
  
  // Convert and compress
  switch (format) {
    case 'webp':
      sharpInstance = sharpInstance.webp({ quality });
      break;
    case 'jpeg':
      sharpInstance = sharpInstance.jpeg({ quality });
      break;
    case 'png':
      sharpInstance = sharpInstance.png({ quality });
      break;
  }
  
  // Strip metadata and return
  return sharpInstance
    .strip() // Remove EXIF data
    .toBuffer();
};

export const getOptimalFormat = (mimetype: string): 'webp' | 'jpeg' | 'png' => {
  if (mimetype.includes('png') || mimetype.includes('gif')) {
    return 'png'; // Preserve transparency
  }
  return 'webp'; // Best compression for photos
};

export const isImage = (mimetype: string): boolean => {
  return mimetype.startsWith('image/');
};
```

**3. Cloudinary Upload** (`middlewares/upload.middleware.ts`)
```typescript
const uploadToCloudinary = (
  buffer: Buffer,
  originalname: string,
  mimetype: string
): Promise<any> => {
  return new Promise((resolve, reject) => {
    // Determine resource type
    let resourceType: 'image' | 'raw' | 'video' | 'auto' = 'auto';
    
    if (mimetype.startsWith('image/')) {
      resourceType = 'image';
    } else if (mimetype.startsWith('video/')) {
      resourceType = 'video';
    } else {
      resourceType = 'raw'; // For PDFs, documents
    }
    
    // Upload stream
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'spacedly/attachments',
        public_id: `${path.parse(originalname).name}-${Date.now()}-${Math.random() * 1e9}`,
        resource_type: resourceType
      },
      (error, result) => {
        if (error) {
          console.error('Cloudinary error:', error);
          return reject(error);
        }
        resolve(result);
      }
    );
    
    // Convert buffer to stream and pipe
    const { Readable } = require('stream');
    const bufferStream = Readable.from(buffer);
    bufferStream.pipe(uploadStream);
  });
};
```

**4. Optimize and Upload Middleware** (`middlewares/upload.middleware.ts`)
```typescript
export const optimizeAndUpload = async (req, res, next) => {
  try {
    const files = req.files as Express.Multer.File[];
    
    if (!files || files.length === 0) {
      return next();
    }
    
    const uploadedFiles = [];
    let totalOriginalSize = 0;
    let totalOptimizedSize = 0;
    
    for (const file of files) {
      const originalSize = file.size;
      totalOriginalSize += originalSize;
      
      if (isImage(file.mimetype)) {
        console.log(`Optimizing: ${file.originalname} (${(originalSize / 1024 / 1024).toFixed(2)}MB)`);
        
        // Optimize with Sharp
        const format = getOptimalFormat(file.mimetype);
        const optimizedBuffer = await optimizeImage(file.buffer, {
          quality: 70,
          maxWidth: 1920,
          maxHeight: 1080,
          format
        });
        
        const optimizedSize = optimizedBuffer.length;
        totalOptimizedSize += optimizedSize;
        const compressionRatio = Math.round(
          ((originalSize - optimizedSize) / originalSize) * 100
        );
        
        console.log(`Optimized: ${(optimizedSize / 1024 / 1024).toFixed(2)}MB (${compressionRatio}% reduction)`);
        
        // Upload to Cloudinary
        const result = await uploadToCloudinary(
          optimizedBuffer,
          file.originalname,
          file.mimetype
        );
        
        uploadedFiles.push({
          ...file,
          path: result.secure_url,
          filename: result.public_id,
          cloudinaryResult: result,
          optimizationStats: {
            originalSize,
            optimizedSize,
            compressionRatio
          }
        });
      } else {
        // Non-image: upload directly
        totalOptimizedSize += originalSize;
        const result = await uploadToCloudinary(
          file.buffer,
          file.originalname,
          file.mimetype
        );
        
        uploadedFiles.push({
          ...file,
          path: result.secure_url,
          filename: result.public_id,
          cloudinaryResult: result
        });
      }
    }
    
    const overallCompression = Math.round(
      ((totalOriginalSize - totalOptimizedSize) / totalOriginalSize) * 100
    );
    
    console.log(`\nTotal: ${files.length} files`);
    console.log(`Original: ${(totalOriginalSize / 1024 / 1024).toFixed(2)}MB`);
    console.log(`Optimized: ${(totalOptimizedSize / 1024 / 1024).toFixed(2)}MB`);
    console.log(`Compression: ${overallCompression}%\n`);
    
    req.files = uploadedFiles;
    req.optimizationStats = {
      totalFiles: files.length,
      totalOriginalSize,
      totalOptimizedSize,
      overallCompression
    };
    
    next();
  } catch (error) {
    console.error('Upload error:', error);
    next(error);
  }
};
```

**5. Service Layer** (`services/task.service.ts`)
```typescript
export const addTaskAttachments = async (
  taskId: string,
  userId: string,
  files: Express.Multer.File[]
) => {
  // Verify task ownership
  const task = await Task.findOne({
    where: { id: taskId, userId }
  });
  
  if (!task) {
    throw new ApiError(404, 'Task not found');
  }
  
  // Create attachment records
  const attachments = await Promise.all(
    files.map(file =>
      TaskAttachment.create({
        taskId,
        filename: file.originalname,
        fileUrl: file.path, // Cloudinary URL
        fileType: file.mimetype,
        fileSize: file.size,
        publicId: file.filename // Cloudinary public_id
      })
    )
  );
  
  return attachments;
};
```

#### **Interview Questions**

**Q1: Why use Sharp for image optimization instead of ImageMagick?**
**A:** Sharp advantages:
- **Faster**: 4-5x faster than ImageMagick
- **Memory efficient**: Streams images, doesn't load entirely in memory
- **Modern**: Uses libvips, optimized for web
- **Node.js native**: Better integration
- **Better compression**: Produces smaller files with same quality

**Q2: What is the difference between buffer and stream?**
**A:**
- **Buffer**: Entire file in memory at once
  - Pro: Easy to work with, can process multiple times
  - Con: Memory intensive for large files
  
- **Stream**: Processes file in chunks
  - Pro: Memory efficient, good for large files
  - Con: More complex code, can only process once

We use buffer for convenience since files are limited to 10MB.

**Q3: Why store files in Cloudinary instead of local disk?**
**A:** Cloudinary benefits:
- **CDN**: Global distribution, faster loading
- **Scalability**: No server storage limits
- **Transformations**: On-the-fly resizing, format conversion
- **Reliability**: Redundancy, backups
- **Cost**: Pay for what you use
- **Mobile**: Optimized delivery for different devices

**Q4: How does WebP provide better compression?**
**A:** WebP uses:
- **Predictive coding**: Predicts pixel values
- **Better algorithms**: VP8/VP9 video codec technology
- **Lossless and lossy**: Supports both
- **Transparency**: Like PNG but smaller
- **Results**: 25-35% smaller than JPEG/PNG

**Q5: What security concerns exist with file uploads?**
**A:**
- **File type validation**: Check extension AND mimetype (can be spoofed)
- **File size limits**: Prevent DoS
- **Malware scanning**: For sensitive applications
- **Storage limits**: Per user quotas
- **File name sanitization**: Prevent path traversal
- **Content scanning**: Check for malicious content in images/PDFs

Our implementation:
- Validates both extension and mimetype
- 10MB file size limit
- Uploads to Cloudinary (isolated from server)
- Strips EXIF data (privacy)

**Q6: Explain the file upload flow in detail.**
**A:**
1. **Client**: User selects files, FormData created
2. **Multer**: Parses multipart data, validates files
3. **Memory Storage**: Files stored in buffer (not disk)
4. **Optimization**: Sharp processes images
5. **Cloudinary**: Upload via streaming
6. **Database**: Store metadata (URL, size, type)
7. **Response**: Return uploaded file details
8. **Client**: Display files with URLs

---

### 5.2 Delete Attachment Flow

#### **Flow Diagram**
```
User clicks delete on attachment
    ↓
DELETE /api/attachments/:attachmentId
    ↓
[Auth Middleware]
    ↓
[Controller] deleteAttachment()
    ↓
[Service] deleteAttachment(attachmentId, userId)
    ↓
[Database Query] Find attachment with task
SELECT a.*, t.user_id 
FROM task_attachments a
JOIN tasks t ON a.task_id = t.id
WHERE a.id = ? AND t.user_id = ?
    ↓
[Not found or user doesn't own task]
    ↓
    throw ApiError(404, "Attachment not found")
    
[Found] ↓
[Extract Cloudinary public_id]
- Parse from fileUrl or use stored publicId
    ↓
[Delete from Cloudinary]
cloudinary.uploader.destroy(public_id, { resource_type: 'auto' })
    ↓
[Cloudinary Response]
- result: 'ok' (deleted)
- result: 'not found' (already deleted)
    ↓
[Delete from Database]
DELETE FROM task_attachments WHERE id = ?
    ↓
[Response] 200 OK
{
  success: true,
  message: "Attachment deleted successfully"
}
```

#### **Code Implementation**

```typescript
export const deleteAttachment = async (
  attachmentId: string,
  userId: string
) => {
  // Find attachment with task to verify ownership
  const attachment = await TaskAttachment.findOne({
    where: { id: attachmentId },
    include: [{
      model: Task,
      as: 'task',
      where: { userId },
      attributes: ['id', 'userId']
    }]
  });
  
  if (!attachment) {
    throw new ApiError(404, 'Attachment not found');
  }
  
  // Delete from Cloudinary
  try {
    const publicId = attachment.publicId;
    await cloudinary.uploader.destroy(publicId, {
      resource_type: 'auto' // Auto-detect if image or raw
    });
  } catch (error) {
    console.error('Cloudinary deletion error:', error);
    // Continue with DB deletion even if Cloudinary fails
  }
  
  // Delete from database
  await attachment.destroy();
  
  return { message: 'Attachment deleted successfully' };
};
```

---

## 6. Reminder & Notification System

### 6.1 Create Reminder Flow

#### **Complete Flow Diagram**
```
User creates reminder for a task
    ↓
POST /api/reminders
Body: {
  taskId: "uuid",
  scheduledAt: "2024-12-10T09:00:00Z",
  type: "email",
  message: "Project deadline reminder"
}
    ↓
[Auth Middleware]
    ↓
[Controller] createReminder()
    ↓
[Validation] Joi Schema
- taskId: required, UUID
- scheduledAt: required, future date
- type: enum ['email', 'push', 'both']
- message: optional, max 500 chars
    ↓
[Service] createReminder()
    ↓
[Verify Task Ownership]
SELECT * FROM tasks WHERE id = ? AND user_id = ?
    ↓
[Task not found] → 404 error
    ↓
[Task found]
[Create Reminder]
INSERT INTO reminders (
  user_id, task_id, scheduled_at, type, 
  message, status, email_sent
) VALUES (?, ?, ?, ?, ?, 'pending', false)
    ↓
[Response] 201 Created
{
  success: true,
  data: {
    reminder: {
      id: "uuid",
      taskId: "uuid",
      scheduledAt: "2024-12-10T09:00:00Z",
      type: "email",
      status: "pending",
      message: "Project deadline reminder"
    }
  },
  message: "Reminder created successfully"
}
    ↓
[Cron Job Running in Background]
- Checks every hour
- Finds pending reminders due for sending
- Sends emails
- Updates status
```

#### **Code Breakdown**

**1. Validation** (`validations/reminder.validation.ts`)
```typescript
export const createReminderSchema = Joi.object({
  taskId: Joi.string()
    .uuid()
    .required()
    .messages({
      'string.guid': 'Invalid task ID format',
      'any.required': 'Task ID is required'
    }),
    
  scheduledAt: Joi.date()
    .iso()
    .min('now')
    .required()
    .messages({
      'date.min': 'Scheduled time must be in the future',
      'any.required': 'Scheduled time is required'
    }),
    
  type: Joi.string()
    .valid('email', 'push', 'both')
    .default('email'),
    
  message: Joi.string()
    .max(500)
    .allow('')
    .optional()
});
```

**2. Service** (`services/reminder.service.ts`)
```typescript
export const createReminder = async (data: {
  userId: string;
  taskId: string;
  scheduledAt: Date;
  type?: string;
  message?: string;
}) => {
  // Verify task ownership
  const task = await Task.findOne({
    where: {
      id: data.taskId,
      userId: data.userId
    }
  });
  
  if (!task) {
    throw new ApiError(404, 'Task not found');
  }
  
  // Create reminder
  const reminder = await Reminder.create({
    userId: data.userId,
    taskId: data.taskId,
    scheduledAt: data.scheduledAt,
    type: data.type || 'email',
    message: data.message,
    status: 'pending',
    emailSent: false
  });
  
  return reminder;
};
```

---

### 6.2 Cron Job System (Automated Email Reminders)

#### **Complete Flow Diagram**
```
[Server Starts]
    ↓
[Initialize Cron Job] startReminderCron()
    ↓
Schedule: '0 * * * *' (Every hour at minute 0)
Example: 1:00, 2:00, 3:00, 4:00, 5:00, ...
    ↓
[Cron Triggers]
    ↓
[Calculate IST Time]
- UTC time + 5.5 hours = IST
- Example: 11:30 PM UTC = 5:00 AM IST
    ↓
[Is it 5:00 AM IST?]
    ↓ Yes
    [Trigger Morning Reminders]
    sendMorningReminders()
        ↓
        [Database Query] Find tasks due today
        SELECT t.*, r.*, u.email, u.name
        FROM reminders r
        JOIN tasks t ON r.task_id = t.id
        JOIN users u ON r.user_id = u.id
        WHERE r.status = 'pending'
          AND r.email_sent = false
          AND DATE(t.due_date) = TODAY()
          AND r.type IN ('email', 'both')
        ORDER BY u.id, t.due_date
            ↓
        [Group by User]
        User1: [Task1, Task2, Task3]
        User2: [Task4]
            ↓
        For each user:
            [Compose Email]
            Subject: "Good Morning! You have 3 tasks due today"
            Body: HTML with task list
                ↓
            [Send Email via Nodemailer]
            sendEmail(user.email, subject, html)
                ↓
            [Update Reminders]
            UPDATE reminders 
            SET email_sent = true, email_sent_at = NOW()
            WHERE id IN (...)
                ↓
        [Return Count]
        Return number of emails sent
    
    ↓ Always (Every Hour)
    [Trigger 1-Hour-Before Reminders]
    sendHourBeforeReminders()
        ↓
        [Database Query] Find tasks due in next hour
        SELECT t.*, r.*, u.email, u.name
        FROM reminders r
        JOIN tasks t ON r.task_id = t.id
        JOIN users u ON r.user_id = u.id
        WHERE r.status = 'pending'
          AND r.email_sent = false
          AND r.scheduled_at BETWEEN NOW() AND NOW() + 1 hour
          AND r.type IN ('email', 'both')
            ↓
        For each reminder:
            [Send Individual Email]
            Subject: "Reminder: [Task Title] is due in 1 hour"
            Body: Task details and deadline
                ↓
            [Update Reminder]
            UPDATE reminders
            SET email_sent = true, 
                email_sent_at = NOW(),
                status = 'completed'
            WHERE id = ?
                ↓
        [Return Count]
            ↓
    [Log Results]
    console.log("Morning emails: 5, Hour-before emails: 2")
        ↓
    [Wait for Next Hour]
    Cron sleeps until next hour
```

#### **Code Breakdown**

**1. Cron Service** (`services/reminderCron.service.ts`)
```typescript
export const startReminderCron = () => {
  // Run every hour at minute 0
  cron.schedule('0 * * * *', async () => {
    try {
      const now = new Date();
      console.log(`\n[Cron] Running at ${now.toISOString()}`);
      
      // Calculate IST time (UTC + 5.5 hours)
      const istOffset = 5.5 * 60 * 60 * 1000;
      const currentIST = new Date(now.getTime() + istOffset);
      const istHour = currentIST.getHours();
      
      // Send morning reminders at 5 AM IST
      if (istHour === 5) {
        console.log('[Cron] 5 AM IST - Sending morning reminders');
        const morningCount = await sendMorningReminders();
        console.log(`[Cron] Morning emails sent: ${morningCount}`);
      }
      
      // Send 1-hour-before reminders (every hour)
      console.log('[Cron] Checking 1-hour-before reminders');
      const hourBeforeCount = await sendHourBeforeReminders();
      console.log(`[Cron] Hour-before emails sent: ${hourBeforeCount}`);
      
    } catch (error) {
      console.error('[Cron Error]:', error);
    }
  });
  
  console.log('✅ Reminder cron started');
  console.log('   - Morning emails: 5:00 AM IST');
  console.log('   - Hour-before: Every hour\n');
};
```

**2. Morning Reminders** (`services/reminderEmail.service.ts`)
```typescript
export const sendMorningReminders = async (): Promise<number> => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  
  // Find all pending reminders for tasks due today
  const reminders = await Reminder.findAll({
    where: {
      status: 'pending',
      emailSent: false,
      type: { [Op.in]: ['email', 'both'] }
    },
    include: [
      {
        model: Task,
        as: 'task',
        where: {
          dueDate: {
            [Op.gte]: today,
            [Op.lt]: tomorrow
          }
        },
        attributes: ['id', 'title', 'dueDate', 'priority', 'category']
      },
      {
        model: User,
        as: 'user',
        attributes: ['id', 'email', 'name']
      }
    ]
  });
  
  if (reminders.length === 0) {
    console.log('[Morning Reminders] No tasks due today');
    return 0;
  }
  
  // Group reminders by user
  const userReminders = groupBy(reminders, 'userId');
  let emailsSent = 0;
  
  for (const [userId, userReminderList] of Object.entries(userReminders)) {
    const user = userReminderList[0].user;
    const tasks = userReminderList.map(r => r.task);
    
    // Compose email
    const subject = `Good Morning! You have ${tasks.length} task${tasks.length > 1 ? 's' : ''} due today`;
    const html = morningReminderTemplate(user.name, tasks);
    
    try {
      // Send email
      await sendEmail(user.email, subject, html);
      emailsSent++;
      
      // Mark emails as sent
      const reminderIds = userReminderList.map(r => r.id);
      await Reminder.update(
        { 
          emailSent: true, 
          emailSentAt: new Date() 
        },
        { where: { id: { [Op.in]: reminderIds } } }
      );
      
      console.log(`[Morning] Email sent to ${user.email} (${tasks.length} tasks)`);
    } catch (error) {
      console.error(`[Morning] Failed to send to ${user.email}:`, error);
    }
  }
  
  return emailsSent;
};
```

**3. Hour-Before Reminders** (`services/reminderEmail.service.ts`)
```typescript
export const sendHourBeforeReminders = async (): Promise<number> => {
  const now = new Date();
  const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);
  
  // Find reminders scheduled in next hour
  const reminders = await Reminder.findAll({
    where: {
      status: 'pending',
      emailSent: false,
      scheduledAt: {
        [Op.gte]: now,
        [Op.lte]: oneHourLater
      },
      type: { [Op.in]: ['email', 'both'] }
    },
    include: [
      {
        model: Task,
        as: 'task',
        attributes: ['id', 'title', 'description', 'dueDate', 'priority']
      },
      {
        model: User,
        as: 'user',
        attributes: ['id', 'email', 'name']
      }
    ]
  });
  
  if (reminders.length === 0) {
    console.log('[Hour-Before] No reminders due');
    return 0;
  }
  
  let emailsSent = 0;
  
  for (const reminder of reminders) {
    const { user, task } = reminder;
    
    // Compose email
    const subject = `Reminder: ${task.title} is due soon`;
    const html = hourBeforeTemplate(
      user.name,
      task.title,
      task.description,
      task.dueDate,
      reminder.message
    );
    
    try {
      // Send email
      await sendEmail(user.email, subject, html);
      emailsSent++;
      
      // Mark as sent and completed
      await reminder.update({
        emailSent: true,
        emailSentAt: new Date(),
        status: 'completed'
      });
      
      console.log(`[Hour-Before] Email sent to ${user.email} for task: ${task.title}`);
    } catch (error) {
      console.error(`[Hour-Before] Failed for ${user.email}:`, error);
    }
  }
  
  return emailsSent;
};
```

**4. Email Templates** (`helpers/emailTemplates.ts`)
```typescript
export const morningReminderTemplate = (
  userName: string,
  tasks: Task[]
) => {
  const taskList = tasks.map(task => `
    <div style="padding: 15px; border-left: 4px solid ${getPriorityColor(task.priority)}; 
                margin: 10px 0; background: #f9f9f9;">
      <h3 style="margin: 0 0 5px 0;">${task.title}</h3>
      <p style="margin: 5px 0; color: #666;">
        <strong>Due:</strong> ${formatTime(task.dueDate)}
      </p>
      <p style="margin: 5px 0; color: #666;">
        <strong>Priority:</strong> 
        <span style="color: ${getPriorityColor(task.priority)}">
          ${task.priority.toUpperCase()}
        </span>
      </p>
      ${task.category ? `<p style="margin: 5px 0; color: #666;">
        <strong>Category:</strong> ${task.category}
      </p>` : ''}
    </div>
  `).join('');
  
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                  padding: 30px; text-align: center; color: white;">
        <h1 style="margin: 0;">Good Morning, ${userName}!</h1>
        <p style="margin: 10px 0 0 0; font-size: 18px;">
          You have ${tasks.length} task${tasks.length > 1 ? 's' : ''} due today
        </p>
      </div>
      
      <div style="padding: 30px;">
        <h2 style="color: #333;">Today's Tasks</h2>
        ${taskList}
        
        <div style="margin-top: 30px; text-align: center;">
          <a href="${process.env.FRONTEND_URL}/tasks" 
             style="background: #667eea; color: white; padding: 12px 30px; 
                    text-decoration: none; border-radius: 5px; display: inline-block;">
            View All Tasks
          </a>
        </div>
      </div>
      
      <div style="padding: 20px; background: #f5f5f5; text-align: center; color: #666;">
        <p style="margin: 0; font-size: 14px;">
          Spacedly - Your Task Management Solution
        </p>
      </div>
    </div>
  `;
};

const getPriorityColor = (priority: string): string => {
  switch (priority) {
    case 'high': return '#e74c3c';
    case 'medium': return '#f39c12';
    case 'low': return '#3498db';
    default: return '#95a5a6';
  }
};
```

#### **Interview Questions**

**Q1: Why use cron instead of database polling?**
**A:**
**Cron advantages:**
- Scheduled, predictable execution
- Doesn't require constant DB queries
- Better resource utilization
- Industry standard for scheduled tasks

**Alternatives:**
- **Database polling**: Constant SELECT queries (inefficient)
- **Queue-based**: Redis/RabbitMQ (more complex but scalable)
- **Cloud functions**: AWS Lambda/Google Cloud Functions (serverless)

**Q2: How would you handle timezone differences?**
**A:** Current approach: Store all dates in UTC, calculate IST for morning emails

Better approach:
```typescript
// Store user timezone in database
user.timezone = 'Asia/Kolkata'

// Use moment-timezone or date-fns-tz
const userTime = moment.tz(user.timezone);
if (userTime.hour() === 5) {
  sendMorningEmail(user);
}
```

**Q3: What happens if email sending fails?**
**A:** Current: Log error, continue to next email

Production approach:
```typescript
try {
  await sendEmail(user.email, subject, html);
  await reminder.update({ emailSent: true });
} catch (error) {
  // Retry logic
  await reminder.update({ 
    retryCount: reminder.retryCount + 1,
    lastError: error.message 
  });
  
  if (reminder.retryCount < 3) {
    // Queue for retry in 1 hour
    await queueRetry(reminder.id);
  }
}
```

**Q4: How to prevent duplicate emails?**
**A:** Multiple safeguards:
1. `emailSent: false` in WHERE clause
2. Update `emailSent = true` immediately after sending
3. Transaction to ensure atomicity
4. Unique constraint on `(reminderId, emailSentAt)`

**Q5: How to scale this system for millions of users?**
**A:**
1. **Use a queue system** (BullMQ, RabbitMQ)
2. **Batch processing**: Process 1000 emails at a time
3. **Multiple workers**: Distribute load across servers
4. **Email service**: Use SendGrid, AWS SES (better deliverability)
5. **Database indexing**: Index on `scheduledAt`, `status`, `emailSent`
6. **Partitioning**: Partition reminders table by date
7. **Caching**: Cache email templates

---

### 6.3 Notification System

#### **Flow Diagram**
```
[Event Occurs]
Examples:
- User completes a task
- Task becomes overdue
- Reminder is sent
    ↓
[Service Layer] Calls notification service
notificationService.createNotification({
  userId,
  type,
  title,
  message,
  relatedTaskId
})
    ↓
[Database Insert]
INSERT INTO notifications (
  user_id, type, title, message, 
  related_task_id, is_read
) VALUES (?, ?, ?, ?, ?, false)
    ↓
[Frontend Polling or WebSocket]
GET /api/notifications
    ↓
[Response] List of notifications
    ↓
[User Clicks on Notification]
PATCH /api/notifications/:id/read
    ↓
[Mark as Read]
UPDATE notifications SET is_read = true WHERE id = ?
    ↓
[Frontend Updates Badge Count]
```

#### **Code Implementation**

**1. Notification Service** (`services/notification.service.ts`)
```typescript
export const createNotification = async (data: {
  userId: string;
  type: 'overdue' | 'upcoming' | 'reminder' | 'general';
  title: string;
  message: string;
  relatedTaskId?: string;
}) => {
  try {
    const notification = await Notification.create(data);
    return notification;
  } catch (error) {
    throw new ApiError(500, 'Failed to create notification');
  }
};

export const getUserNotifications = async (userId: string) => {
  const notifications = await Notification.findAll({
    where: { userId },
    include: [
      {
        model: Task,
        as: 'task',
        attributes: ['id', 'title']
      }
    ],
    order: [['createdAt', 'DESC']],
    limit: 50 // Latest 50 notifications
  });
  
  return notifications;
};

export const getUnreadCount = async (userId: string) => {
  const count = await Notification.count({
    where: {
      userId,
      isRead: false
    }
  });
  
  return count;
};

export const markAsRead = async (notificationId: string, userId: string) => {
  const notification = await Notification.findOne({
    where: { id: notificationId, userId }
  });
  
  if (!notification) {
    throw new ApiError(404, 'Notification not found');
  }
  
  notification.isRead = true;
  await notification.save();
  
  return notification;
};

export const markAllAsRead = async (userId: string) => {
  await Notification.update(
    { isRead: true },
    { where: { userId, isRead: false } }
  );
  
  return { message: 'All notifications marked as read' };
};
```

**2. Usage Example**
```typescript
// In task service when task is completed
export const updateTask = async (taskId, userId, updateData) => {
  const task = await Task.findOne({ where: { id: taskId, userId } });
  
  const wasCompleted = task.status !== 'completed' && 
                       updateData.status === 'completed';
  
  await task.update(updateData);
  
  // Create notification
  if (wasCompleted) {
    await notificationService.createNotification({
      userId,
      type: 'general',
      title: 'Task Completed',
      message: `You completed: ${task.title}`,
      relatedTaskId: task.id
    });
  }
  
  return task;
};
```

#### **Interview Questions**

**Q1: How would you implement real-time notifications?**
**A:** Options:
1. **WebSockets** (Socket.io):
```typescript
io.on('connection', (socket) => {
  socket.on('authenticate', (userId) => {
    socket.join(`user:${userId}`);
  });
});

// Emit notification
io.to(`user:${userId}`).emit('notification', notificationData);
```

2. **Server-Sent Events (SSE)**:
```typescript
app.get('/notifications/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  // Send notifications as they occur
});
```

3. **Long Polling**: Frontend polls every 30 seconds

**Q2: How to prevent notification spam?**
**A:**
- **Batching**: Group similar notifications
- **Rate limiting**: Max notifications per hour
- **User preferences**: Let users control notification types
- **Digest mode**: Daily summary instead of real-time
- **Deduplication**: Don't send duplicate notifications

**Q3: How to handle notification delivery failure?**
**A:**
- Store in database first (always successful)
- Retry mechanism for push/email
- Fallback to in-app notification
- Log delivery status
- Allow manual resend

---

## 7. Analytics & Reporting

### 7.1 Analytics Data Flow (with Caching)

#### **Complete Flow Diagram**
```
User navigates to Analytics page
    ↓
GET /api/analytics
    ↓
[Auth Middleware]
    ↓
[Controller] getAnalytics()
    ↓
[Service] getAnalytics(userId)
    ↓
[Check Cache]
cacheKey = `analytics:${userId}`
const cached = await cacheService.get(cacheKey)
    ↓
[Cache Hit?]
    ↓ Yes (Data exists in cache)
    Parse cached JSON
    Return data immediately
    (Total time: ~5ms)
    
    ↓ No (Cache miss)
    [Database Queries - Run in Parallel]
    
    [Query 1] Total Tasks Count
    SELECT COUNT(*) FROM tasks WHERE user_id = ?
    
    [Query 2] Reminder Stats
    SELECT 
      COUNT(*) FILTER (WHERE status = 'completed') as completed,
      COUNT(*) FILTER (WHERE status = 'pending' AND scheduled_at > NOW()) as upcoming,
      COUNT(*) FILTER (WHERE status = 'pending' AND scheduled_at < NOW()) as overdue
    FROM reminders WHERE user_id = ?
    
    [Query 3] Daily Data (Last 7 days)
    For each of last 7 days:
      SELECT COUNT(*) 
      FROM reminders 
      WHERE user_id = ?
        AND status = 'completed'
        AND scheduled_at BETWEEN ? AND ?
    
    [Query 4] Weekly Data (Last 4 weeks)
    For each of last 4 weeks:
      SELECT COUNT(*)
      FROM reminders
      WHERE user_id = ?
        AND status = 'completed'
        AND scheduled_at BETWEEN ? AND ?
    
    [Query 5] Category Distribution
    SELECT category, COUNT(*) as count
    FROM tasks
    WHERE user_id = ?
    GROUP BY category
        ↓
    [Aggregate Results]
    analyticsData = {
      totalTasks: 45,
      completedReminders: 120,
      upcomingReminders: 15,
      overdueReminders: 3,
      dailyData: [
        { date: 'Dec 1', completed: 5 },
        { date: 'Dec 2', completed: 8 },
        ...
      ],
      weeklyData: [
        { week: 'Week 1', completed: 28 },
        { week: 'Week 2', completed: 35 },
        ...
      ],
      categoryData: [
        { category: 'Work', count: 20, percent: 0.44 },
        { category: 'Personal', count: 15, percent: 0.33 },
        ...
      ]
    }
        ↓
    [Cache Result]
    await cacheService.set(cacheKey, JSON.stringify(analyticsData), 300)
    // TTL: 300 seconds (5 minutes)
        ↓
    [Return Data]
    (Total time: ~150ms first time, ~5ms subsequent)
        ↓
    [Response] 200 OK
    {
      success: true,
      data: analyticsData
    }
        ↓
Frontend renders charts and stats
```

#### **Code Breakdown**

**1. Analytics Service** (`services/analytics.service.ts`)
```typescript
export const getAnalytics = async (userId: string) => {
  try {
    // Check cache first
    const cacheKey = `analytics:${userId}`;
    const cached = await cacheService.get(cacheKey);
    
    if (cached) {
      console.log('[Analytics] Cache hit');
      return JSON.parse(cached);
    }
    
    console.log('[Analytics] Cache miss - querying database');
    
    const now = new Date();
    
    // Run queries in parallel for better performance
    const [
      totalTasks,
      completedReminders,
      upcomingReminders,
      overdueReminders,
      dailyData,
      weeklyData,
      categoryData
    ] = await Promise.all([
      Task.count({ where: { userId } }),
      
      Reminder.count({
        where: { userId, status: 'completed' }
      }),
      
      Reminder.count({
        where: {
          userId,
          status: 'pending',
          scheduledAt: { [Op.gt]: now }
        }
      }),
      
      Reminder.count({
        where: {
          userId,
          status: 'pending',
          scheduledAt: { [Op.lt]: now }
        }
      }),
      
      getDailyData(userId),
      getWeeklyData(userId),
      getCategoryData(userId)
    ]);
    
    const analyticsData = {
      totalTasks,
      completedReminders,
      upcomingReminders,
      overdueReminders,
      dailyData,
      weeklyData,
      categoryData
    };
    
    // Cache for 5 minutes
    await cacheService.set(cacheKey, JSON.stringify(analyticsData), 300);
    
    return analyticsData;
  } catch (error) {
    console.error('[Analytics Error]:', error);
    throw new ApiError(500, 'Failed to fetch analytics');
  }
};
```

**2. Daily Data Aggregation**
```typescript
const getDailyData = async (userId: string) => {
  const now = new Date();
  const dailyData = [];
  
  for (let i = 0; i < 7; i++) {
    const date = new Date(now);
    date.setDate(now.getDate() - i);
    
    const startOfDay = new Date(date.setHours(0, 0, 0, 0));
    const endOfDay = new Date(date.setHours(23, 59, 59, 999));
    
    const completed = await Reminder.count({
      where: {
        userId,
        status: 'completed',
        scheduledAt: {
          [Op.between]: [startOfDay, endOfDay]
        }
      }
    });
    
    dailyData.unshift({
      date: startOfDay.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric' 
      }),
      completed
    });
  }
  
  return dailyData;
};
```

**3. Category Distribution**
```typescript
const getCategoryData = async (userId: string) => {
  const tasks = await Task.findAll({
    where: { userId },
    attributes: ['category'],
    raw: true
  });
  
  // Count by category
  const categoryCounts = {};
  const totalCount = tasks.length;
  
  tasks.forEach(task => {
    const category = task.category || 'Uncategorized';
    categoryCounts[category] = (categoryCounts[category] || 0) + 1;
  });
  
  // Calculate percentages
  const categoryData = Object.entries(categoryCounts).map(
    ([category, count]) => ({
      category,
      count,
      percent: totalCount > 0 ? count / totalCount : 0
    })
  );
  
  return categoryData;
};
```

**4. Cache Service** (`services/cache.service.ts`)
```typescript
class CacheService {
  private cache: NodeCache;
  
  constructor() {
    this.cache = new NodeCache({
      stdTTL: 300, // Default 5 minutes
      checkperiod: 60, // Check for expired keys every 60s
      useClones: false // Better performance
    });
  }
  
  async get(key: string): Promise<string | null> {
    const value = this.cache.get<string>(key);
    if (value) {
      console.log(`[Cache] Hit: ${key}`);
      return value;
    }
    console.log(`[Cache] Miss: ${key}`);
    return null;
  }
  
  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl) {
      this.cache.set(key, value, ttl);
    } else {
      this.cache.set(key, value);
    }
    console.log(`[Cache] Set: ${key} (TTL: ${ttl || 'default'}s)`);
  }
  
  async delPattern(pattern: string): Promise<void> {
    const keys = this.cache.keys().filter(key => key.includes(pattern));
    if (keys.length > 0) {
      this.cache.del(keys);
      console.log(`[Cache] Deleted ${keys.length} keys matching: ${pattern}`);
    }
  }
}

export const cacheService = new CacheService();
```

#### **Interview Questions**

**Q1: Why use caching for analytics?**
**A:**
- **Performance**: Reduces database load
- **User experience**: Faster page loads (5ms vs 150ms)
- **Cost**: Fewer database queries
- **Scalability**: Can handle more concurrent users

**Q2: What is the difference between Redis and NodeCache?**
**A:**
**NodeCache:**
- In-memory, single server
- Simple, no external dependencies
- Lost on server restart
- Good for small-scale applications

**Redis:**
- External cache server
- Persistent (can survive restart)
- Distributed (multiple servers)
- Advanced features (pub/sub, sorted sets)
- Production-ready for large scale

**Q3: When should you invalidate cache?**
**A:**
- When task is created/updated/deleted
- When reminder is created/updated
- Use pattern-based deletion: `analytics:${userId}`
- Balance between freshness and performance

**Q4: How would you optimize the getDailyData query?**
**A:** Current approach: 7 separate queries

Optimized approach (single query):
```typescript
const dailyData = await Reminder.findAll({
  where: {
    userId,
    status: 'completed',
    scheduledAt: {
      [Op.gte]: sevenDaysAgo
    }
  },
  attributes: [
    [sequelize.fn('DATE', sequelize.col('scheduledAt')), 'date'],
    [sequelize.fn('COUNT', '*'), 'completed']
  ],
  group: [sequelize.fn('DATE', sequelize.col('scheduledAt'))],
  raw: true
});
```

**Q5: What is Promise.all and why use it?**
**A:**
```typescript
// Sequential (slow)
const tasks = await getTasks();        // 50ms
const reminders = await getReminders(); // 50ms
const analytics = await getAnalytics(); // 50ms
// Total: 150ms

// Parallel (fast)
const [tasks, reminders, analytics] = await Promise.all([
  getTasks(),
  getReminders(),
  getAnalytics()
]);
// Total: 50ms (all run simultaneously)
```

Benefits:
- Runs promises concurrently
- Waits for all to complete
- Fails fast (if any promise rejects)
- Better resource utilization

---

### 7.2 Streak Calculation

#### **Algorithm Flow**
```
[Query] Get all completed reminders
SELECT * FROM reminders
WHERE user_id = ? AND status = 'completed'
ORDER BY scheduled_at DESC
    ↓
[Group by Day]
Map: {
  '2024-12-06': 3 reminders,
  '2024-12-05': 2 reminders,
  '2024-12-04': 5 reminders,
  '2024-12-02': 1 reminder,  // Gap on 12-03
  '2024-12-01': 2 reminders
}
    ↓
[Calculate Active Streak]
today = '2024-12-06'
yesterday = '2024-12-05'

If latest completion is today or yesterday:
  activeStreak = 1
  currentDate = latest date
  
  For each previous day:
    expectedDate = currentDate - 1 day
    If expectedDate exists in map:
      activeStreak++
      currentDate = expectedDate
    Else:
      break (gap found)
else:
  activeStreak = 0 (no activity recently)
    ↓
Example calculation:
- 12-06: exists ✓ → streak = 1
- 12-05: exists ✓ → streak = 2
- 12-04: exists ✓ → streak = 3
- 12-03: missing ✗ → stop
Active streak = 3 days
    ↓
[Calculate Longest Streak]
currentStreak = 1
longestStreak = 1
previousDate = first date

For each subsequent date:
  dayDiff = previousDate - currentDate
  
  If dayDiff == 1 day:
    currentStreak++
    longestStreak = max(longestStreak, currentStreak)
  else:
    currentStreak = 1 (gap, restart count)
  
  previousDate = currentDate
    ↓
Example:
- 12-06 to 12-05: diff = 1 ✓ → current = 2, longest = 2
- 12-05 to 12-04: diff = 1 ✓ → current = 3, longest = 3
- 12-04 to 12-02: diff = 2 ✗ → current = 1, longest = 3
- 12-02 to 12-01: diff = 1 ✓ → current = 2, longest = 3

Longest streak = 3 days
    ↓
[Return]
{
  active: 3,
  longest: 3
}
```

#### **Code Implementation**

```typescript
export const getStreaks = async (userId: string) => {
  try {
    const now = new Date();
    let activeStreak = 0;
    let longestStreak = 0;
    let currentStreak = 0;
    
    // Get all completed reminders
    const completedReminders = await Reminder.findAll({
      where: {
        userId,
        status: 'completed'
      },
      order: [['scheduledAt', 'DESC']],
      raw: true
    });
    
    if (completedReminders.length === 0) {
      return { active: 0, longest: 0 };
    }
    
    // Group by day
    const dayMap = new Map<string, number>();
    completedReminders.forEach(reminder => {
      const date = new Date(reminder.scheduledAt);
      const dayKey = date.toISOString().split('T')[0]; // YYYY-MM-DD
      dayMap.set(dayKey, (dayMap.get(dayKey) || 0) + 1);
    });
    
    const sortedDays = Array.from(dayMap.keys()).sort().reverse();
    
    // Calculate active streak
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(now.setDate(now.getDate() - 1))
      .toISOString().split('T')[0];
    
    if (sortedDays[0] === today || sortedDays[0] === yesterday) {
      activeStreak = 1;
      let checkDate = new Date(sortedDays[0]);
      
      for (let i = 1; i < sortedDays.length; i++) {
        checkDate.setDate(checkDate.getDate() - 1);
        const expectedDate = checkDate.toISOString().split('T')[0];
        
        if (sortedDays[i] === expectedDate) {
          activeStreak++;
        } else {
          break;
        }
      }
    }
    
    // Calculate longest streak
    currentStreak = 1;
    longestStreak = 1;
    let prevDate = new Date(sortedDays[0]);
    
    for (let i = 1; i < sortedDays.length; i++) {
      const currentDate = new Date(sortedDays[i]);
      const diffTime = Math.abs(prevDate.getTime() - currentDate.getTime());
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      
      if (diffDays === 1) {
        currentStreak++;
        longestStreak = Math.max(longestStreak, currentStreak);
      } else {
        currentStreak = 1;
      }
      
      prevDate = currentDate;
    }
    
    return {
      active: activeStreak,
      longest: longestStreak
    };
  } catch (error) {
    console.error('[Streaks Error]:', error);
    throw new ApiError(500, 'Failed to fetch streaks');
  }
};
```

#### **Interview Questions**

**Q1: How would you optimize streak calculation for millions of users?**
**A:**
1. **Materialized view**: Pre-calculate and store
```sql
CREATE MATERIALIZED VIEW user_streaks AS
SELECT 
  user_id,
  calculate_active_streak(user_id) as active,
  calculate_longest_streak(user_id) as longest
FROM users;

REFRESH MATERIALIZED VIEW user_streaks; -- Run daily
```

2. **Incremental updates**: Update only when reminder is completed
```typescript
// When reminder is completed
await updateUserStreak(userId);
```

3. **Database function**: Calculate in PostgreSQL
```sql
CREATE FUNCTION calculate_streak(user_id UUID) 
RETURNS TABLE(active INT, longest INT) AS $$
  -- Streak calculation logic in SQL
$$ LANGUAGE plpgsql;
```

**Q2: What edge cases should you consider for streaks?**
**A:**
- User has no completed reminders
- User completed only today
- User has gaps in completion history
- Timezone differences (user travels)
- Multiple completions same day (should count as 1)
- Leap years / month boundaries
- User deletes old reminders

**Q3: How to handle timezone for streak calculation?**
**A:**
```typescript
// Store user timezone
user.timezone = 'America/New_York';

// Convert to user's timezone before grouping
const userDate = moment.tz(reminder.scheduledAt, user.timezone);
const dayKey = userDate.format('YYYY-MM-DD');
```

---

## 8. Important Libraries & Tools Deep Dive

### 8.1 Express.js

**What**: Minimal web framework for Node.js

**How it works**:
```typescript
const app = express();

// Middleware stack
app.use(middleware1);  // Executes first
app.use(middleware2);  // Then this
app.use(middleware3);  // Then this

// Route handling
app.get('/api/users', handler);  // Matches GET /api/users
```

**Why use it**:
- De facto standard for Node.js web apps
- Huge ecosystem of middleware
- Flexible and unopinionated
- Great performance
- Easy to learn

**When to use**:
- Building REST APIs
- Server-side rendered apps
- Microservices
- Webhooks and integrations

**Alternatives**:
- **Fastify**: Faster, schema-based
- **Koa**: Smaller, modern (by Express creators)
- **NestJS**: Full framework with TypeScript
- **Hapi**: More structured, plugin-based

---

### 8.2 Sequelize ORM

**What**: Object-Relational Mapping for SQL databases

**How it works**:
```typescript
// Define model
class User extends Model {
  @Column
  name!: string;
}

// Query
const users = await User.findAll({
  where: { active: true },
  include: ['posts']
});

// Generates SQL:
// SELECT * FROM users WHERE active = true
// SELECT * FROM posts WHERE user_id IN (...)
```

**Why use it**:
- Write JavaScript instead of SQL
- Database agnostic (PostgreSQL, MySQL, SQLite)
- Automatic migrations
- Built-in validations
- Type safety with TypeScript
- Prevents SQL injection

**When to use**:
- Complex data models with relationships
- Need database portability
- Team not SQL experts
- Rapid prototyping

**When NOT to use**:
- Complex queries (use raw SQL)
- High performance requirements
- Small simple apps (overhead not worth it)

**Alternatives**:
- **TypeORM**: Similar, more TypeScript-focused
- **Prisma**: Modern, type-safe, better DX
- **Knex.js**: Query builder (lower level)
- **Raw SQL**: Maximum control and performance

**Key Concepts**:
```typescript
// Associations
User.hasMany(Task);  // One user, many tasks
Task.belongsTo(User);  // Task belongs to user

// Eager loading (avoid N+1)
User.findAll({ include: ['tasks'] });

// Transactions
await sequelize.transaction(async (t) => {
  await User.create({ name: 'John' }, { transaction: t });
  await Task.create({ userId: 1 }, { transaction: t });
});
```

---

### 8.3 JSON Web Tokens (jsonwebtoken)

**What**: Secure way to transmit information between parties as JSON

**How it works**:
```typescript
// Structure: header.payload.signature
// Example: eyJhbGc...(header).eyJ1c2Vy...(payload).SflKxwRJ...(signature)

// Creating token
const token = jwt.sign(
  { userId: 123, email: 'user@example.com' },  // Payload
  'secret-key',  // Secret
  { expiresIn: '15m' }  // Options
);

// Verifying token
const decoded = jwt.verify(token, 'secret-key');
// decoded = { userId: 123, email: 'user@example.com', iat: ..., exp: ... }
```

**Why use it**:
- Stateless (no server-side session storage)
- Self-contained (all info in token)
- Can't be tampered (signature verification)
- Works across services (microservices)
- Standard format (RFC 7519)

**When to use**:
- API authentication
- Single Sign-On (SSO)
- Information exchange
- Temporary access grants

**Security Considerations**:
- Never store sensitive data in payload (it's base64, not encrypted)
- Use HTTPS to prevent token interception
- Short expiration times
- Refresh token pattern for long sessions
- Verify signature on every request

**Common Mistakes**:
```typescript
// ❌ Bad: Storing password in token
jwt.sign({ userId: 1, password: 'hash' }, secret);

// ✅ Good: Only non-sensitive data
jwt.sign({ userId: 1, email: 'user@email.com' }, secret);

// ❌ Bad: Too long expiration
{ expiresIn: '30d' }

// ✅ Good: Short-lived with refresh token
{ expiresIn: '15m' }
```

---

### 8.4 bcryptjs

**What**: Library to hash passwords

**How it works**:
```typescript
// Hashing
const salt = await bcrypt.genSalt(10);  // 10 rounds
const hash = await bcrypt.hash('password123', salt);
// Result: $2a$10$N9qo8uLOickgx2ZMRZoMye...

// Comparing
const isValid = await bcrypt.compare('password123', hash);
// true
```

**Why use it**:
- **Slow by design**: Makes brute force impractical
- **Adaptive**: Can increase rounds as hardware improves
- **Salted**: Each hash unique (prevents rainbow tables)
- **One-way**: Can't reverse to get original password

**Salt Rounds**:
- More rounds = more secure but slower
- 10 rounds: ~100ms (good for 2025)
- 12 rounds: ~400ms (very secure)
- Each +1 doubles the time

**When to use**:
- Password hashing
- Any credential storage

**When NOT to use**:
- Encrypting data (use crypto instead)
- Hashing large data (use crypto.createHash)
- Real-time verification (too slow)

**Security Best Practices**:
```typescript
// ✅ Good: Async, proper salt
const hash = await bcrypt.hash(password, 10);

// ❌ Bad: Sync (blocks event loop)
const hash = bcrypt.hashSync(password, 10);

// ❌ Bad: No salt
const hash = crypto.createHash('sha256').update(password).digest('hex');
```

---

### 8.5 Joi Validation

**What**: Schema description and data validation

**How it works**:
```typescript
const schema = Joi.object({
  email: Joi.string().email().required(),
  age: Joi.number().min(18).max(100),
  password: Joi.string()
    .min(6)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .required()
});

const result = schema.validate(data);
if (result.error) {
  // Validation failed
  console.log(result.error.details);
}
```

**Why use it**:
- Declarative schema definition
- Rich validation rules
- Custom error messages
- Type coercion
- Works with TypeScript
- Industry standard

**When to use**:
- API input validation
- Configuration validation
- Form validation
- Data sanitization

**Common Patterns**:
```typescript
// Conditional validation
Joi.when('type', {
  is: 'email',
  then: Joi.string().email(),
  otherwise: Joi.string().alphanum()
});

// Custom validation
Joi.string().custom((value, helpers) => {
  if (value === 'admin') {
    return helpers.error('any.invalid');
  }
  return value;
});

// References
Joi.object({
  password: Joi.string(),
  confirmPassword: Joi.ref('password')
});
```

**Alternatives**:
- **Yup**: Similar API, smaller
- **Zod**: TypeScript-first
- **Ajv**: JSON Schema validator (faster)
- **Validator.js**: Simple string validation

---

### 8.6 Passport.js

**What**: Authentication middleware for Node.js

**How it works**:
```typescript
// Configure strategy
passport.use(new GoogleStrategy({
  clientID: '...',
  clientSecret: '...',
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  const user = await findOrCreateUser(profile);
  done(null, user);
}));

// Use in routes
app.get('/auth/google', passport.authenticate('google'));
app.get('/auth/google/callback', 
  passport.authenticate('google'),
  (req, res) => {
    // req.user contains authenticated user
  }
);
```

**Why use it**:
- 500+ authentication strategies
- Handles OAuth flow complexity
- Session management
- Well-tested and maintained
- Modular design

**When to use**:
- OAuth integration (Google, Facebook, GitHub)
- Local authentication
- JWT authentication
- Multi-provider authentication

**Strategies We Use**:
- **passport-google-oauth20**: Google OAuth
- **passport-jwt**: JWT authentication (could use)
- **passport-local**: Username/password (could use)

**Session vs JWT**:
```typescript
// Session-based (traditional)
passport.use(session());
// Stores user ID in session

// JWT-based (modern, what we do)
passport.authenticate('google', { session: false })
// Stateless, no server-side storage
```

---

### 8.7 Multer

**What**: Middleware for handling multipart/form-data (file uploads)

**How it works**:
```typescript
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Not an image'));
    }
  }
});

// Use in route
app.post('/upload', upload.single('file'), (req, res) => {
  // req.file contains uploaded file
  // req.file.buffer contains file data
});
```

**Why use it**:
- Built for Express
- Multiple storage options
- File filtering
- Size limits
- Field name mapping

**Storage Options**:
```typescript
// Memory storage (our choice for processing)
multer.memoryStorage()
// Stores in buffer, can process with Sharp

// Disk storage
multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
})
// Saves directly to disk
```

**When to use**:
- Image uploads
- Document uploads
- CSV imports
- Any file handling

**Security**:
```typescript
// ✅ Validate file type
fileFilter: (req, file, cb) => {
  const allowed = /jpeg|jpg|png|pdf/;
  const ext = allowed.test(path.extname(file.originalname));
  const mime = allowed.test(file.mimetype);
  if (ext && mime) cb(null, true);
  else cb(new Error('Invalid file type'));
}

// ✅ Limit file size
limits: { fileSize: 10 * 1024 * 1024 }  // 10MB

// ✅ Limit number of files
upload.array('files', 5)  // Max 5 files
```

---

### 8.8 Sharp

**What**: High-performance image processing library

**How it works**:
```typescript
await sharp('input.jpg')
  .resize(1920, 1080, { fit: 'inside' })
  .webp({ quality: 80 })
  .toFile('output.webp');

// From buffer
const optimized = await sharp(buffer)
  .rotate()  // Auto-rotate based on EXIF
  .resize(800, 600)
  .jpeg({ quality: 85 })
  .toBuffer();
```

**Why use it**:
- **Fast**: 4-5x faster than ImageMagick
- **Memory efficient**: Streaming architecture
- **Modern formats**: WebP, AVIF support
- **Comprehensive**: Resize, crop, rotate, blur, etc.
- **Node-native**: C++ bindings

**When to use**:
- Image optimization
- Thumbnail generation
- Format conversion
- Image manipulation

**Common Operations**:
```typescript
// Resize
.resize(width, height, {
  fit: 'cover',  // cover, contain, fill, inside, outside
  position: 'center'
})

// Format conversion
.webp({ quality: 80 })
.jpeg({ quality: 85 })
.png({ compressionLevel: 9 })

// Metadata
.rotate()  // Auto-rotate based on EXIF
.strip()   // Remove EXIF data

// Effects
.blur(5)
.sharpen()
.normalize()
.grayscale()
```

**Why WebP**:
- 25-35% smaller than JPEG/PNG
- Supports transparency (like PNG)
- Lossy and lossless modes
- Wide browser support (95%+)

**Performance Tips**:
```typescript
// ✅ Chain operations (faster)
sharp(buffer)
  .resize(800, 600)
  .webp({ quality: 80 })
  .toBuffer();

// ❌ Multiple Sharp instances (slower)
const resized = await sharp(buffer).resize(800, 600).toBuffer();
const optimized = await sharp(resized).webp({ quality: 80 }).toBuffer();
```

---

### 8.9 Cloudinary

**What**: Cloud-based image and video management

**How it works**:
```typescript
// Upload
const result = await cloudinary.uploader.upload('image.jpg', {
  folder: 'products',
  public_id: 'item-123',
  transformation: [
    { width: 1000, crop: 'scale' },
    { quality: 'auto' }
  ]
});

// URL: https://res.cloudinary.com/demo/image/upload/v1234/products/item-123.jpg

// Delete
await cloudinary.uploader.destroy('products/item-123');

// Get URL with transformations
const url = cloudinary.url('products/item-123', {
  width: 400,
  height: 400,
  crop: 'fill',
  gravity: 'face',
  quality: 'auto',
  fetch_format: 'auto'
});
```

**Why use it**:
- **CDN**: Global distribution, fast loading
- **Transformations**: On-the-fly resizing, cropping
- **Responsive**: Automatic format and quality
- **Storage**: No server disk space needed
- **Backup**: Redundant, reliable
- **Free tier**: 25GB storage, 25GB bandwidth

**When to use**:
- User-generated content
- E-commerce product images
- Profile pictures
- Any image/video hosting

**Key Features**:
```typescript
// Responsive images
c_scale,w_auto,dpr_auto

// Face detection
g_face,c_thumb

// Auto quality
q_auto

// Auto format (WebP for Chrome, JPEG for Safari)
f_auto

// Lazy loading
l_text:Arial_60:Loading...,co_grey
```

**Alternatives**:
- **AWS S3 + CloudFront**: More control, more setup
- **Imgix**: Similar to Cloudinary
- **ImageKit**: Similar to Cloudinary
- **Local + CDN**: Custom solution

---

### 8.10 Nodemailer

**What**: Email sending library for Node.js

**How it works**:
```typescript
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,  // true for 465, false for other ports
  auth: {
    user: 'your-email@gmail.com',
    pass: 'app-password'  // Not regular password
  }
});

await transporter.sendMail({
  from: '"App Name" <no-reply@app.com>',
  to: 'user@example.com',
  subject: 'Welcome!',
  text: 'Plain text version',
  html: '<b>HTML version</b>'
});
```

**Why use it**:
- Simple API
- Supports all major email services
- HTML emails
- Attachments
- Custom headers
- Well-maintained

**Email Providers**:
```typescript
// Gmail (free, 500/day limit)
{ service: 'gmail', auth: { user, pass } }

// SendGrid (better for production)
{ host: 'smtp.sendgrid.net', auth: { user: 'apikey', pass: API_KEY } }

// AWS SES (cheapest at scale)
{ host: 'email-smtp.us-east-1.amazonaws.com', auth: { user, pass } }

// Mailgun, Postmark, etc.
```

**When to use**:
- Transactional emails (password reset, OTP)
- Welcome emails
- Notifications
- Reports

**Best Practices**:
```typescript
// ✅ Use app password for Gmail, not account password
// ✅ HTML + text fallback
html: htmlVersion,
text: textVersion

// ✅ Proper from address
from: '"Company Name" <no-reply@company.com>'

// ✅ Handle errors
try {
  await sendEmail();
} catch (error) {
  console.error('Email error:', error);
  // Log to monitoring service
  // Maybe queue for retry
}

// ✅ Use templates
const html = emailTemplate({ name: user.name, link: resetLink });
```

**Production Considerations**:
- Use dedicated email service (SendGrid, AWS SES)
- Queue emails for async processing
- Monitor deliverability
- Handle bounces and complaints
- Rate limit to prevent spam classification

---

### 8.11 node-cron

**What**: Task scheduler for Node.js (like Linux cron)

**How it works**:
```typescript
// Cron format: second minute hour day month weekday
// * * * * * *
// │ │ │ │ │ │
// │ │ │ │ │ └─ Weekday (0-6, Sunday=0)
// │ │ │ │ └─── Month (1-12)
// │ │ │ └───── Day (1-31)
// │ │ └─────── Hour (0-23)
// │ └───────── Minute (0-59)
// └─────────── Second (0-59, optional)

// Every hour at minute 0
cron.schedule('0 * * * *', () => {
  console.log('Running every hour');
});

// Every day at 5:00 AM
cron.schedule('0 5 * * *', () => {
  console.log('Running at 5 AM');
});

// Every Monday at 9:00 AM
cron.schedule('0 9 * * 1', () => {
  console.log('Running every Monday at 9 AM');
});
```

**Why use it**:
- Simple syntax
- Built for Node.js
- Start/stop jobs programmatically
- Timezone support
- No external dependencies

**When to use**:
- Scheduled tasks (daily reports)
- Cleanup jobs (delete old files)
- Data synchronization
- Reminder emails
- Cache warming

**Common Patterns**:
```typescript
// Every 15 minutes
'*/15 * * * *'

// Every day at midnight
'0 0 * * *'

// Every weekday at 9 AM
'0 9 * * 1-5'

// First day of month
'0 0 1 * *'

// With timezone
cron.schedule('0 9 * * *', () => {}, {
  timezone: 'America/New_York'
});
```

**Alternatives**:
- **node-schedule**: More features
- **Agenda**: MongoDB-backed, distributed
- **Bull**: Redis-backed queue + scheduler
- **AWS EventBridge**: Cloud-based

**Production Considerations**:
```typescript
// ✅ Error handling
cron.schedule('* * * * *', async () => {
  try {
    await heavyTask();
  } catch (error) {
    console.error('Cron error:', error);
    // Log to monitoring
  }
});

// ✅ Prevent overlapping runs
let isRunning = false;
cron.schedule('* * * * *', async () => {
  if (isRunning) return;
  isRunning = true;
  try {
    await task();
  } finally {
    isRunning = false;
  }
});

// ✅ Graceful shutdown
const job = cron.schedule('* * * * *', task);
process.on('SIGTERM', () => job.stop());
```

---

### 8.12 NodeCache

**What**: Simple in-memory cache for Node.js

**How it works**:
```typescript
const cache = new NodeCache({
  stdTTL: 300,  // 5 minutes default TTL
  checkperiod: 60  // Check for expired keys every 60s
});

// Set
cache.set('key', 'value', 600);  // Custom TTL (10 min)

// Get
const value = cache.get('key');  // Returns value or undefined

// Delete
cache.del('key');

// Stats
cache.getStats();
// { keys: 10, hits: 100, misses: 5, ... }
```

**Why use it**:
- Fast (in-memory)
- Simple API
- No external dependencies
- TTL support
- Statistics

**When to use**:
- Small to medium apps
- Single-server deployments
- Session storage (small scale)
- API response caching
- Computed values

**When NOT to use**:
- Multi-server (not shared)
- Large datasets (memory limit)
- Persistent cache needed
- Distributed systems

**Best Practices**:
```typescript
// ✅ Cache expensive operations
const getCachedAnalytics = async (userId) => {
  const cached = cache.get(`analytics:${userId}`);
  if (cached) return JSON.parse(cached);
  
  const data = await expensiveDatabaseQuery(userId);
  cache.set(`analytics:${userId}`, JSON.stringify(data), 300);
  return data;
};

// ✅ Pattern-based deletion
const keys = cache.keys().filter(key => key.startsWith('user:'));
cache.del(keys);

// ✅ Error handling
try {
  cache.set('key', 'value');
} catch (error) {
  // Cache failure shouldn't break app
  console.error('Cache error:', error);
}
```

**vs Redis**:
| Feature | NodeCache | Redis |
|---------|-----------|-------|
| Speed | Very fast | Fast |
| Persistence | No | Yes |
| Distribution | Single server | Multi-server |
| Features | Basic | Rich (pub/sub, sorted sets) |
| Setup | None | External service |
| Use case | Small apps | Production, scale |

---

### 8.13 Helmet

**What**: Security middleware that sets HTTP headers

**How it works**:
```typescript
app.use(helmet());

// Sets these headers:
// Content-Security-Policy
// X-DNS-Prefetch-Control
// X-Frame-Options: DENY
// X-Download-Options
// X-Content-Type-Options: nosniff
// X-XSS-Protection
```

**Why use it**:
- Protects against common vulnerabilities
- One line of code
- Configurable
- Best practice
- Used by major companies

**What it prevents**:
- **XSS**: Content Security Policy
- **Clickjacking**: X-Frame-Options
- **MIME sniffing**: X-Content-Type-Options
- **DNS prefetching**: X-DNS-Prefetch-Control

**Configuration**:
```typescript
helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "cdn.example.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  hsts: {
    maxAge: 31536000,  // 1 year
    includeSubDomains: true
  }
})
```

**When to use**: Always in production

---

### 8.14 express-rate-limit

**What**: Rate limiting middleware for Express

**How it works**:
```typescript
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,  // Limit each IP to 100 requests per window
  message: 'Too many requests',
  standardHeaders: true,  // Return rate limit info in headers
  legacyHeaders: false
});

app.use('/api/', limiter);
```

**Why use it**:
- Prevents brute force attacks
- Prevents DoS attacks
- Protects server resources
- Easy to implement
- Configurable per route

**Strategies**:
```typescript
// IP-based (default)
rateLimit({ ... })

// User-based
rateLimit({
  keyGenerator: (req) => req.user?.id || req.ip
})

// Custom store (Redis for multi-server)
const RedisStore = require('rate-limit-redis');
rateLimit({
  store: new RedisStore({ client: redisClient })
})
```

**Best Practices**:
```typescript
// ✅ Different limits for different routes
const authLimiter = rateLimit({ max: 5 });  // Strict
const apiLimiter = rateLimit({ max: 100 });  // Lenient

app.use('/auth/', authLimiter);
app.use('/api/', apiLimiter);

// ✅ Skip successful requests
rateLimit({
  skipSuccessfulRequests: true  // Only count failures
})

// ✅ Custom error response
rateLimit({
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many requests',
      retryAfter: res.getHeader('Retry-After')
    });
  }
})
```

---

### 8.15 CORS

**What**: Cross-Origin Resource Sharing middleware

**How it works**:
```typescript
app.use(cors({
  origin: 'https://example.com',  // Allow this origin
  methods: ['GET', 'POST'],  // Allow these methods
  credentials: true  // Allow cookies
}));

// Browser makes request from different origin
// CORS middleware adds headers:
// Access-Control-Allow-Origin: https://example.com
// Access-Control-Allow-Methods: GET,POST
// Access-Control-Allow-Credentials: true
```

**Why needed**:
Browser security prevents cross-origin requests by default.
CORS middleware tells browser: "This cross-origin request is okay"

**Configuration**:
```typescript
// Single origin
cors({ origin: 'https://example.com' })

// Multiple origins
cors({ 
  origin: ['https://app.com', 'https://admin.app.com']
})

// Dynamic origin check
cors({
  origin: (origin, callback) => {
    const whitelist = ['https://app.com', 'https://mobile.app.com'];
    if (whitelist.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
})

// Allow all (⚠️ only for development)
cors({ origin: '*' })
```

**When to use**: When frontend and backend on different domains

---

## 9. Database Schema & Associations

### 8.1 Database Tables

#### **Users Table**
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255),
  google_id VARCHAR(255) UNIQUE,
  auth_provider VARCHAR(50) DEFAULT 'local',
  is_two_factor_enabled BOOLEAN DEFAULT false,
  two_factor_otp VARCHAR(6),
  two_factor_otp_expiry TIMESTAMP,
  refresh_token TEXT,
  reset_password_token VARCHAR(255),
  reset_password_expires TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_google_id ON users(google_id);
```

#### **Tasks Table**
```sql
CREATE TABLE tasks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  due_date TIMESTAMP NOT NULL,
  priority VARCHAR(20) DEFAULT 'medium',
  category VARCHAR(50),
  status VARCHAR(20) DEFAULT 'todo',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_tasks_user_id ON tasks(user_id);
CREATE INDEX idx_tasks_due_date ON tasks(due_date);
CREATE INDEX idx_tasks_status ON tasks(status);
```

#### **Task Attachments Table**
```sql
CREATE TABLE task_attachments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  file_url TEXT NOT NULL,
  file_type VARCHAR(100),
  file_size INTEGER,
  public_id VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_attachments_task_id ON task_attachments(task_id);
```

#### **Reminders Table**
```sql
CREATE TABLE reminders (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  task_id UUID REFERENCES tasks(id) ON DELETE CASCADE,
  scheduled_at TIMESTAMP NOT NULL,
  type VARCHAR(20) DEFAULT 'email',
  message TEXT,
  status VARCHAR(20) DEFAULT 'pending',
  email_sent BOOLEAN DEFAULT false,
  email_sent_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_reminders_user_id ON reminders(user_id);
CREATE INDEX idx_reminders_task_id ON reminders(task_id);
CREATE INDEX idx_reminders_scheduled_at ON reminders(scheduled_at);
CREATE INDEX idx_reminders_status_email ON reminders(status, email_sent);
```

#### **Notifications Table**
```sql
CREATE TABLE notifications (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  title VARCHAR(200) NOT NULL,
  message TEXT NOT NULL,
  related_task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
  is_read BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_is_read ON notifications(is_read);
```

### 8.2 Entity Relationships

```
users (1) ──< (M) tasks
users (1) ──< (M) reminders
users (1) ──< (M) notifications

tasks (1) ──< (M) task_attachments
tasks (1) ──< (M) reminders
tasks (1) ──< (M) notifications (optional)
```

---

## 9. Database Operations & Migrations

### 9.1 Complete ORM to SQL Translation (Project Queries)

Based on our actual project code, here are all the Sequelize queries and their SQL equivalents:

---

#### **USER SERVICE QUERIES**

**1. User Registration**
```typescript
// ORM (user.service.ts - userRegister)
const existingUser = await User.findOne({ where: { email } });
const user = await User.create({ 
  name, 
  email, 
  password: hashpassword,
  auth_provider: 'local'
});

// SQL Equivalent
-- Check if user exists
SELECT * FROM users WHERE email = 'john@example.com' LIMIT 1;

-- Create new user
INSERT INTO users (
  id, name, email, password, auth_provider, 
  is_two_factor_enabled, created_at, updated_at
) VALUES (
  uuid_generate_v4(), 'John Doe', 'john@example.com', 
  '$2a$10$...', 'local', false, NOW(), NOW()
) RETURNING *;
```

**2. User Login**
```typescript
// ORM (user.service.ts - userLogin)
const user = await User.findOne({ where: { email } });
user.refresh_token = refreshToken;
await user.save();

// SQL Equivalent
-- Find user
SELECT * FROM users WHERE email = 'john@example.com' LIMIT 1;

-- Update refresh token
UPDATE users 
SET refresh_token = 'jwt-refresh-token', 
    updated_at = NOW()
WHERE id = 'user-uuid';
```

**3. Find User by Primary Key (Auth Middleware)**
```typescript
// ORM (middlewares/auth.middleware.ts)
const user = await User.findByPk(decodedRefresh.id);

// SQL Equivalent
SELECT * FROM users WHERE id = 'user-uuid' LIMIT 1;
```

**4. Forgot Password**
```typescript
// ORM (user.service.ts - forgotPasswordService)
const user = await User.findOne({ where: { email } });
user.reset_password_token = hashedToken;
user.reset_password_expires = new Date(Date.now() + 60 * 60 * 1000);
await user.save();

// SQL Equivalent
-- Find user by email
SELECT * FROM users WHERE email = 'john@example.com' LIMIT 1;

-- Update reset token fields
UPDATE users 
SET reset_password_token = 'hashed-token',
    reset_password_expires = NOW() + INTERVAL '1 hour',
    updated_at = NOW()
WHERE id = 'user-uuid';
```

**5. Reset Password**
```typescript
// ORM (user.service.ts - resetPasswordService)
const user = await User.findOne({
  where: { reset_password_token: hashedToken }
});
user.password = hashedPassword;
user.reset_password_token = null;
user.reset_password_expires = null;
user.refresh_token = null;
await user.save();

// SQL Equivalent
-- Find user by reset token
SELECT * FROM users WHERE reset_password_token = 'hashed-token' LIMIT 1;

-- Update password and clear reset fields
UPDATE users 
SET password = '$2a$10$new-hash',
    reset_password_token = NULL,
    reset_password_expires = NULL,
    refresh_token = NULL,
    updated_at = NOW()
WHERE id = 'user-uuid';
```

**6. Two-Factor Authentication**
```typescript
// ORM (user.service.ts - verifyTwoFactorOtp)
const user = await User.findOne({ where: { email } });
user.two_factor_otp = null;
user.two_factor_otp_expiry = null;
user.refresh_token = refreshToken;
await user.save();

// SQL Equivalent
-- Find user
SELECT * FROM users WHERE email = 'john@example.com' LIMIT 1;

-- Clear OTP and set refresh token
UPDATE users 
SET two_factor_otp = NULL,
    two_factor_otp_expiry = NULL,
    refresh_token = 'jwt-refresh-token',
    updated_at = NOW()
WHERE id = 'user-uuid';
```

---

#### **TASK SERVICE QUERIES**

**1. Create Task**
```typescript
// ORM (task.service.ts - createTask)
const task = await Task.create(taskData);

// SQL Equivalent
INSERT INTO tasks (
  id, user_id, title, description, category, 
  priority, link, created_at, updated_at
) VALUES (
  uuid_generate_v4(), 'user-uuid', 'Complete project', 
  'Finish the backend', 'Work', 'High', 
  'https://github.com/...', NOW(), NOW()
) RETURNING *;
```

**2. Get All User Tasks with Attachments**
```typescript
// ORM (task.service.ts - getAllUserTasks)
const tasks = await Task.findAll({
  where: { userId },
  include: [{
    model: TaskAttachment,
    as: 'attachments',
    attributes: ['id', 'fileName', 'originalName', 'fileSize', 'fileType', 'fileUrl']
  }],
  order: [['createdAt', 'DESC']]
});

// SQL Equivalent
SELECT 
  t.id, t.user_id, t.title, t.description, t.category, 
  t.priority, t.link, t.created_at, t.updated_at,
  a.id AS "attachments.id",
  a.file_name AS "attachments.fileName",
  a.original_name AS "attachments.originalName",
  a.file_size AS "attachments.fileSize",
  a.file_type AS "attachments.fileType",
  a.file_url AS "attachments.fileUrl"
FROM tasks t
LEFT OUTER JOIN task_attachments a ON t.id = a.task_id
WHERE t.user_id = 'user-uuid'
ORDER BY t.created_at DESC;
```

**3. Get Task by ID**
```typescript
// ORM (task.service.ts - getTaskById)
const task = await Task.findOne({
  where: { id: taskId, userId },
  include: [{
    model: TaskAttachment,
    as: 'attachments',
    attributes: ['id', 'fileName', 'originalName', 'fileSize', 'fileType', 'fileUrl']
  }]
});

// SQL Equivalent
SELECT 
  t.*,
  a.id AS "attachments.id",
  a.file_name AS "attachments.fileName",
  a.original_name AS "attachments.originalName",
  a.file_size AS "attachments.fileSize",
  a.file_type AS "attachments.fileType",
  a.file_url AS "attachments.fileUrl"
FROM tasks t
LEFT OUTER JOIN task_attachments a ON t.id = a.task_id
WHERE t.id = 'task-uuid' AND t.user_id = 'user-uuid'
LIMIT 1;
```

**4. Update Task**
```typescript
// ORM (task.service.ts - updateTask)
const task = await Task.findOne({ where: { id: taskId, userId } });
await task.update(updateData);

// SQL Equivalent
-- Find task
SELECT * FROM tasks 
WHERE id = 'task-uuid' AND user_id = 'user-uuid' 
LIMIT 1;

-- Update task
UPDATE tasks 
SET title = 'Updated title',
    description = 'Updated description',
    category = 'Personal',
    priority = 'Low',
    updated_at = NOW()
WHERE id = 'task-uuid';
```

**5. Delete Task with CASCADE**
```typescript
// ORM (task.service.ts - deleteTask)
const task = await Task.findOne({
  where: { id: taskId, userId },
  include: [{ model: TaskAttachment, as: 'attachments' }]
});
await task.destroy();

// SQL Equivalent
-- Find task with attachments
SELECT 
  t.*,
  a.id AS "attachments.id",
  a.file_name AS "attachments.fileName"
FROM tasks t
LEFT OUTER JOIN task_attachments a ON t.id = a.task_id
WHERE t.id = 'task-uuid' AND t.user_id = 'user-uuid';

-- Delete task (CASCADE deletes attachments and reminders automatically)
DELETE FROM tasks WHERE id = 'task-uuid';

-- Due to ON DELETE CASCADE in foreign keys, these happen automatically:
-- DELETE FROM task_attachments WHERE task_id = 'task-uuid';
-- DELETE FROM reminders WHERE task_id = 'task-uuid';
```

**6. Add Task Attachments**
```typescript
// ORM (task.service.ts - addTaskAttachments)
const task = await Task.findOne({ where: { id: taskId, userId } });
const attachment = await TaskAttachment.create({
  taskId,
  fileName: file.filename,
  originalName: file.originalname,
  fileSize: file.size,
  fileType: file.mimetype,
  fileUrl: file.path
});

// SQL Equivalent
-- Verify task ownership
SELECT * FROM tasks WHERE id = 'task-uuid' AND user_id = 'user-uuid' LIMIT 1;

-- Create attachment
INSERT INTO task_attachments (
  id, task_id, file_name, original_name, 
  file_size, file_type, file_url, created_at
) VALUES (
  uuid_generate_v4(), 'task-uuid', 'cloudinary-public-id', 
  'document.pdf', 524288, 'application/pdf', 
  'https://cloudinary.com/...', NOW()
) RETURNING *;
```

**7. Delete Attachment**
```typescript
// ORM (task.service.ts - deleteAttachment)
const attachment = await TaskAttachment.findOne({
  where: { id: attachmentId },
  include: [{ model: Task, as: 'task', where: { userId } }]
});
await attachment.destroy();

// SQL Equivalent
-- Find attachment with task verification
SELECT 
  a.*,
  t.id AS "task.id",
  t.user_id AS "task.user_id"
FROM task_attachments a
INNER JOIN tasks t ON a.task_id = t.id
WHERE a.id = 'attachment-uuid' AND t.user_id = 'user-uuid'
LIMIT 1;

-- Delete attachment
DELETE FROM task_attachments WHERE id = 'attachment-uuid';
```

---

#### **REMINDER SERVICE QUERIES**

**1. Create Reminder**
```typescript
// ORM (reminder.service.ts - createReminder)
const task = await Task.findOne({
  where: { id: taskId, userId }
});
const reminder = await Reminder.create(reminderData);

// SQL Equivalent
-- Verify task ownership
SELECT * FROM tasks WHERE id = 'task-uuid' AND user_id = 'user-uuid' LIMIT 1;

-- Create reminder
INSERT INTO reminders (
  id, user_id, task_id, scheduled_at, 
  status, email_sent, created_at, updated_at
) VALUES (
  uuid_generate_v4(), 'user-uuid', 'task-uuid', 
  '2024-12-10 09:00:00', 'pending', false, NOW(), NOW()
) RETURNING *;
```

**2. Get All User Reminders**
```typescript
// ORM (reminder.service.ts - getAllUserReminders)
const reminders = await Reminder.findAll({
  where: { userId },
  include: [{ model: Task, as: 'task' }],
  order: [['scheduledAt', 'ASC']]
});

// SQL Equivalent
SELECT 
  r.*,
  t.id AS "task.id",
  t.title AS "task.title",
  t.description AS "task.description",
  t.category AS "task.category",
  t.priority AS "task.priority"
FROM reminders r
LEFT OUTER JOIN tasks t ON r.task_id = t.id
WHERE r.user_id = 'user-uuid'
ORDER BY r.scheduled_at ASC;
```

**3. Get Task Reminders**
```typescript
// ORM (reminder.service.ts - getTaskReminders)
const task = await Task.findOne({ where: { id: taskId, userId } });
const reminders = await Reminder.findAll({
  where: { taskId },
  order: [['scheduledAt', 'ASC']]
});

// SQL Equivalent
-- Verify task
SELECT * FROM tasks WHERE id = 'task-uuid' AND user_id = 'user-uuid' LIMIT 1;

-- Get reminders
SELECT * FROM reminders 
WHERE task_id = 'task-uuid' 
ORDER BY scheduled_at ASC;
```

**4. Update Reminder**
```typescript
// ORM (reminder.service.ts - updateReminder)
const reminder = await Reminder.findOne({
  where: { id: reminderId, userId }
});
await reminder.update(updateData);

// SQL Equivalent
-- Find reminder
SELECT * FROM reminders WHERE id = 'reminder-uuid' AND user_id = 'user-uuid' LIMIT 1;

-- Update reminder
UPDATE reminders 
SET scheduled_at = '2024-12-11 10:00:00',
    status = 'completed',
    updated_at = NOW()
WHERE id = 'reminder-uuid';
```

**5. Delete Reminder**
```typescript
// ORM (reminder.service.ts - deleteReminder)
const reminder = await Reminder.findOne({
  where: { id: reminderId, userId }
});
await reminder.destroy();

// SQL Equivalent
-- Find reminder
SELECT * FROM reminders WHERE id = 'reminder-uuid' AND user_id = 'user-uuid' LIMIT 1;

-- Delete reminder
DELETE FROM reminders WHERE id = 'reminder-uuid';
```

---

#### **ANALYTICS SERVICE QUERIES**

**1. Count Total Tasks**
```typescript
// ORM (analytics.service.ts - getAnalytics)
const totalTasks = await Task.count({
  where: { userId }
});

// SQL Equivalent
SELECT COUNT(*) FROM tasks WHERE user_id = 'user-uuid';
```

**2. Count Completed Reminders**
```typescript
// ORM (analytics.service.ts)
const completedReminders = await Reminder.count({
  where: {
    userId,
    status: 'completed'
  }
});

// SQL Equivalent
SELECT COUNT(*) FROM reminders 
WHERE user_id = 'user-uuid' AND status = 'completed';
```

**3. Count Upcoming Reminders**
```typescript
// ORM (analytics.service.ts)
const upcomingReminders = await Reminder.count({
  where: {
    userId,
    status: 'pending',
    scheduledAt: { [Op.gt]: now }
  }
});

// SQL Equivalent
SELECT COUNT(*) FROM reminders 
WHERE user_id = 'user-uuid' 
  AND status = 'pending' 
  AND scheduled_at > NOW();
```

**4. Count Overdue Reminders**
```typescript
// ORM (analytics.service.ts)
const overdueReminders = await Reminder.count({
  where: {
    userId,
    status: 'pending',
    scheduledAt: { [Op.lt]: now }
  }
});

// SQL Equivalent
SELECT COUNT(*) FROM reminders 
WHERE user_id = 'user-uuid' 
  AND status = 'pending' 
  AND scheduled_at < NOW();
```

**5. Daily Completed Reminders (Last 7 Days)**
```typescript
// ORM (analytics.service.ts - getDailyData)
for (let i = 0; i < 7; i++) {
  const completed = await Reminder.count({
    where: {
      userId,
      status: 'completed',
      scheduledAt: {
        [Op.between]: [startOfDay, endOfDay]
      }
    }
  });
}

// SQL Equivalent (for one day)
SELECT COUNT(*) FROM reminders 
WHERE user_id = 'user-uuid' 
  AND status = 'completed' 
  AND scheduled_at BETWEEN '2024-12-06 00:00:00' AND '2024-12-06 23:59:59';
```

**6. Weekly Completed Reminders (Last 4 Weeks)**
```typescript
// ORM (analytics.service.ts - getWeeklyData)
for (let i = 0; i < 4; i++) {
  const completed = await Reminder.count({
    where: {
      userId,
      status: 'completed',
      scheduledAt: {
        [Op.between]: [weekStart, weekEnd]
      }
    }
  });
}

// SQL Equivalent (for one week)
SELECT COUNT(*) FROM reminders 
WHERE user_id = 'user-uuid' 
  AND status = 'completed' 
  AND scheduled_at BETWEEN '2024-11-30 00:00:00' AND '2024-12-06 23:59:59';
```

**7. Category Distribution**
```typescript
// ORM (analytics.service.ts - getCategoryData)
const tasks = await Task.findAll({
  where: { userId },
  attributes: ['category'],
  raw: true
});

// SQL Equivalent
SELECT category FROM tasks WHERE user_id = 'user-uuid';

// Note: Grouping and counting is done in JavaScript in our implementation
// But it could be done in SQL like this:
SELECT category, COUNT(*) as count 
FROM tasks 
WHERE user_id = 'user-uuid' 
GROUP BY category;
```

**8. Get Streaks (All Completed Reminders)**
```typescript
// ORM (analytics.service.ts - getStreaks)
const completedReminders = await Reminder.findAll({
  where: {
    userId,
    status: 'completed'
  },
  order: [['scheduledAt', 'DESC']],
  raw: true
});

// SQL Equivalent
SELECT * FROM reminders 
WHERE user_id = 'user-uuid' AND status = 'completed' 
ORDER BY scheduled_at DESC;
```

---

### 9.2 Database Migration System - Complete Flow

#### **Migration Execution Flow - Step by Step**

When you run `npx sequelize-cli db:migrate`, here's exactly what happens:

```
Developer runs: npx sequelize-cli db:migrate
    ↓
[Step 1] Sequelize CLI reads .sequelizerc config
- Identifies migrations folder: src/migrations
- Identifies config file: src/config/config.js
    ↓
[Step 2] Connect to Database
- Read database credentials from config.js
- Establish connection to PostgreSQL
    ↓
[Step 3] Check/Create SequelizeMeta Table
IF SequelizeMeta table doesn't exist:
    CREATE TABLE "SequelizeMeta" (
      name VARCHAR(255) PRIMARY KEY
    );
    
This table tracks which migrations have been run:
| name                                      |
|-------------------------------------------|
| 20251201073614-create-users-table.js    |
| 20251202075000-create-tasks-table.js    |
    ↓
[Step 4] Query SequelizeMeta for Executed Migrations
SELECT name FROM "SequelizeMeta" ORDER BY name;
    ↓
Returns list: ['20251201073614-create-users-table.js', ...]
    ↓
[Step 5] Scan Migrations Directory
Read all files from src/migrations/
    ↓
[Step 6] Determine Pending Migrations
Compare files with SequelizeMeta records
    ↓
Pending migrations = All migrations NOT in SequelizeMeta
    ↓
[Step 7] Execute Pending Migrations (In Order)
For each pending migration file:
    ↓
    [7a] Load migration file
    const migration = require('./20251203164240-add-email-tracking.js');
    ↓
    [7b] Start Database Transaction
    BEGIN;
    ↓
    [7c] Execute migration.up() function
    await queryInterface.addColumn('reminders', 'email_sent', {
      type: Sequelize.BOOLEAN,
      defaultValue: false
    });
    
    Executes SQL:
    ALTER TABLE reminders ADD COLUMN email_sent BOOLEAN DEFAULT false;
    ↓
    [7d] Record migration as completed
    INSERT INTO "SequelizeMeta" (name) 
    VALUES ('20251203164240-add-email-tracking.js');
    ↓
    [7e] Commit Transaction
    COMMIT;
    ↓
    Success → Move to next pending migration
    Error → ROLLBACK; Stop execution; Report error
    ↓
[Step 8] All Pending Migrations Completed
Display: "All migrations executed successfully"
    ↓
Database schema is now up to date!
```

#### **Rollback Flow - db:migrate:undo**

When you run `npx sequelize-cli db:migrate:undo`:

```
Developer runs: npx sequelize-cli db:migrate:undo
    ↓
[Step 1] Connect to Database
    ↓
[Step 2] Query Last Executed Migration
SELECT name FROM "SequelizeMeta" 
ORDER BY name DESC 
LIMIT 1;
    ↓
Returns: '20251204050403-create-notifications-table.js'
    ↓
[Step 3] Load Migration File
const migration = require('./20251204050403-create-notifications-table.js');
    ↓
[Step 4] Start Transaction
BEGIN;
    ↓
[Step 5] Execute migration.down() function
await queryInterface.dropTable('notifications');
    
Executes SQL:
DROP TABLE notifications;
    ↓
[Step 6] Remove from SequelizeMeta
DELETE FROM "SequelizeMeta" 
WHERE name = '20251204050403-create-notifications-table.js';
    ↓
[Step 7] Commit Transaction
COMMIT;
    ↓
Success → "Migration rolled back successfully"
Error → ROLLBACK; Report error
```

#### **What are Migrations?**
Migrations are version control for your database schema. They allow you to:
- Track database changes over time
- Share schema changes with team
- Rollback changes if needed
- Keep development/staging/production in sync

#### **Migration File Structure**
```javascript
// migrations/20251201073614-create-users-table.js
module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Code to apply migration (create table, add column, etc.)
    await queryInterface.createTable('users', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true
      },
      name: {
        type: Sequelize.STRING(255),
        allowNull: false
      },
      email: {
        type: Sequelize.STRING(255),
        allowNull: false,
        unique: true
      },
      password: {
        type: Sequelize.STRING(255)
      },
      created_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updated_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });
    
    // Add indexes
    await queryInterface.addIndex('users', ['email']);
  },
  
  down: async (queryInterface, Sequelize) => {
    // Code to rollback migration
    await queryInterface.dropTable('users');
  }
};
```

#### **Running Migrations**
```bash
# Create a new migration
npx sequelize-cli migration:generate --name create-users-table

# Run pending migrations
npx sequelize-cli db:migrate

# Rollback last migration
npx sequelize-cli db:migrate:undo

# Rollback all migrations
npx sequelize-cli db:migrate:undo:all

# Check migration status
npx sequelize-cli db:migrate:status
```

#### **Our Project Migrations**
```javascript
// 1. Create Users Table
'20251201073614-create-users-table.js'

// 2. Create Tasks Table
'20251202075000-create-tasks-table.js'

// 3. Create Task Attachments Table
'20251202075100-create-task-attachments-table.js'

// 4. Create Reminders Table
'20251202075200-create-reminders-table.js'

// 5. Add Email Tracking to Reminders
'20251203164240-add-email-tracking-to-reminders.js'

// 6. Create Notifications Table
'20251204050403-create-notifications-table.js'
```

#### **Adding a New Column (Migration Example)**
```javascript
// Migration: Add profile_image to users
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn('users', 'profile_image', {
      type: Sequelize.STRING(500),
      allowNull: true
    });
  },
  
  down: async (queryInterface, Sequelize) => {
    await queryInterface.removeColumn('users', 'profile_image');
  }
};
```

---

### 9.3 Sequelize Models Deep Dive

#### **Model Definition**
```typescript
import { Model, Column, Table, PrimaryKey, Default, DataType, ForeignKey, BelongsTo } from 'sequelize-typescript';

@Table({ tableName: 'tasks', timestamps: true })
class Task extends Model {
  @PrimaryKey
  @Default(DataType.UUIDV4)
  @Column(DataType.UUID)
  id!: string;

  @ForeignKey(() => User)
  @Column(DataType.UUID)
  userId!: string;

  @Column(DataType.STRING(200))
  title!: string;

  @BelongsTo(() => User)
  user!: User;
}
```

#### **Decorators Explained**
- `@Table`: Defines table name and options
- `@Column`: Defines a column
- `@PrimaryKey`: Marks primary key
- `@ForeignKey`: Defines foreign key relationship
- `@Default`: Sets default value
- `@BelongsTo`, `@HasMany`: Defines associations

---

### 9.4 Database Interview Questions

**Q1: What is a Primary Key?**
**A:** Unique identifier for each row in a table.
- Must be unique
- Cannot be NULL
- Each table should have one
- Can be composite (multiple columns)

Our implementation: UUIDs for security and distribution

**Q2: What is a Foreign Key?**
**A:** Column that references primary key in another table.
- Enforces referential integrity
- Prevents orphaned records
- Can have CASCADE actions

Example:
```sql
task_id UUID REFERENCES tasks(id) ON DELETE CASCADE
```

**Q3: What is CASCADE DELETE?**
**A:** When parent record deleted, automatically delete child records.

Example: Delete user → all their tasks deleted automatically

**Q4: What is the difference between DELETE and TRUNCATE?**
**A:**
- **DELETE**: Removes rows one by one, can have WHERE clause, triggers, slower, can rollback
- **TRUNCATE**: Removes all rows at once, faster, can't rollback, resets auto-increment

**Q5: Explain ACID properties.**
**A:**
- **Atomicity**: All or nothing (transaction succeeds completely or fails completely)
- **Consistency**: Database remains in valid state
- **Isolation**: Transactions don't interfere with each other
- **Durability**: Committed data persists even after crash

**Q6: What is database normalization?**
**A:** Process of organizing data to reduce redundancy.

Forms:
- **1NF**: No repeating groups, atomic values
- **2NF**: No partial dependencies
- **3NF**: No transitive dependencies

Our database is in 3NF.

**Q7: What is an Index and when to use it?**
**A:** Data structure that improves query speed.

Use on:
- Primary keys (automatic)
- Foreign keys
- Columns in WHERE clauses
- Columns in ORDER BY

Don't overuse:
- Slows INSERT/UPDATE
- Takes storage space

**Q8: What is the difference between INNER JOIN and LEFT JOIN?**
**A:**
```sql
-- INNER JOIN: Only matching rows
SELECT * FROM tasks t
INNER JOIN users u ON t.user_id = u.id;

-- LEFT JOIN: All from left table + matching from right
SELECT * FROM tasks t
LEFT JOIN task_attachments a ON t.id = a.task_id;
```

**Q9: What is a transaction?**
**A:** Group of operations that execute as a single unit.

```typescript
await sequelize.transaction(async (t) => {
  await User.create({ name: 'John' }, { transaction: t });
  await Task.create({ userId: 1 }, { transaction: t });
  // Both succeed or both fail
});
```

**Q10: How do you prevent SQL injection?**
**A:**
1. Use parameterized queries (Sequelize does this)
2. Never concatenate user input into SQL
3. Use ORM
4. Input validation

```typescript
// ✅ Safe (Sequelize parameterizes)
User.findOne({ where: { email: userInput } });

// ❌ Dangerous (raw SQL)
sequelize.query(`SELECT * FROM users WHERE email = '${userInput}'`);
```

**Q11: What is database connection pooling?**
**A:** Reusing database connections instead of creating new ones.

Benefits:
- Faster (connection reuse)
- Resource efficient
- Limits max connections
- Handles concurrency

**Q12: Explain database indexes types.**
**A:**
- **B-Tree**: Default, good for ranges
- **Hash**: Fast equality lookups
- **GiST/GIN**: Full-text search
- **Partial**: Index subset of rows

---

### 9.5 Advanced SQL Queries

#### **Subqueries**
```sql
-- Find users with more than 5 tasks
SELECT * FROM users
WHERE id IN (
  SELECT user_id FROM tasks
  GROUP BY user_id
  HAVING COUNT(*) > 5
);
```

#### **Window Functions**
```sql
-- Rank tasks by due date per user
SELECT 
  title,
  user_id,
  due_date,
  ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY due_date) as rank
FROM tasks;
```

#### **Common Table Expressions (CTE)**
```sql
WITH completed_tasks AS (
  SELECT user_id, COUNT(*) as count
  FROM tasks
  WHERE status = 'completed'
  GROUP BY user_id
)
SELECT u.name, ct.count
FROM users u
JOIN completed_tasks ct ON u.id = ct.user_id;
```

---

## 10. Production Ready Configuration

### 10.1 Environment Setup

#### **Environment Variables Structure**
```env
# Application
NODE_ENV=production
PORT=3000
FRONTEND_URL=https://app.yourdomain.com
ALLOWED_ORIGINS=https://app.yourdomain.com,https://www.yourdomain.com

# Database
DATABASE_URL=postgresql://user:password@host:5432/dbname
DB_POOL_MAX=20
DB_POOL_MIN=5

# JWT Secrets (Generate with: openssl rand -base64 32)
JWT_ACCESS_SECRET=your-super-secure-access-secret-at-least-32-chars
JWT_REFRESH_SECRET=your-super-secure-refresh-secret-at-least-32-chars

# Email (SendGrid for production)
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=SG.your-sendgrid-api-key

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Google OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret

# Redis (if using)
REDIS_URL=redis://localhost:6379

# Monitoring
SENTRY_DSN=https://your-sentry-dsn
LOG_LEVEL=info
```

#### **Environment File Organization**
```
.env.example        # Template with dummy values (commit to git)
.env.development    # Development config
.env.staging        # Staging config
.env.production     # Production config (NEVER commit)
.env                # Local overrides (NEVER commit)
```

---

### 10.2 Production Configurations

#### **Database Configuration**
```typescript
// config/database.ts
export default {
  development: {
    url: process.env.DATABASE_URL,
    dialect: 'postgres',
    logging: console.log,
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  },
  production: {
    url: process.env.DATABASE_URL,
    dialect: 'postgres',
    logging: false, // Disable SQL logging in production
    pool: {
      max: 20,      // Higher for production
      min: 5,
      acquire: 30000,
      idle: 10000
    },
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false // For cloud databases
      }
    }
  }
};
```

#### **CORS Configuration**
```typescript
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];

app.use(cors({
  origin: (origin, callback) => {
    if (process.env.NODE_ENV === 'development') {
      return callback(null, true); // Allow all in dev
    }
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

#### **Logging Configuration**
```typescript
// Use Winston for production logging
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    // Write to files
    new winston.transports.File({ 
      filename: 'error.log', 
      level: 'error' 
    }),
    new winston.transports.File({ 
      filename: 'combined.log' 
    })
  ]
});

// Console logging in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}
```

---

### 10.3 Security Best Practices

#### **Security Headers (Helmet)**
```typescript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
}));
```

#### **Rate Limiting Strategy**
```typescript
// Use Redis store for production (distributed rate limiting)
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';

const redisClient = new Redis(process.env.REDIS_URL);

const limiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:'
  }),
  windowMs: 15 * 60 * 1000,
  max: 100
});
```

---

### 10.4 Performance Optimization

#### **Compression**
```typescript
import compression from 'compression';

app.use(compression({
  level: 6, // Compression level (0-9)
  threshold: 1024 // Only compress if larger than 1KB
}));
```

#### **Response Time Monitoring**
```typescript
import responseTime from 'response-time';

app.use(responseTime((req, res, time) => {
  if (time > 1000) {
    logger.warn(`Slow request: ${req.method} ${req.url} - ${time}ms`);
  }
}));
```

#### **Database Query Optimization**
```typescript
// Use indexes
await queryInterface.addIndex('tasks', ['user_id', 'status']);

// Select only needed columns
Task.findAll({
  attributes: ['id', 'title', 'status'],
  where: { userId }
});

// Use pagination
Task.findAll({
  limit: 20,
  offset: page * 20
});

// Use database-level aggregation
Task.count({ where: { userId } });
```

---

### 10.5 Deployment Checklist

#### **Pre-Deployment**
- [ ] All environment variables set
- [ ] Database migrations run
- [ ] SSL certificates configured
- [ ] Error monitoring (Sentry) configured
- [ ] Logging service configured
- [ ] Health check endpoint implemented
- [ ] Backup strategy in place
- [ ] Load testing completed
- [ ] Security audit completed

#### **Environment Variables Checklist**
- [ ] `NODE_ENV=production`
- [ ] Strong JWT secrets (32+ chars)
- [ ] Database connection string
- [ ] SMTP credentials
- [ ] OAuth credentials
- [ ] Cloudinary credentials
- [ ] Allowed origins whitelist
- [ ] Rate limit configurations

#### **Security Checklist**
- [ ] HTTPS enforced
- [ ] CORS properly configured
- [ ] Rate limiting enabled
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention (ORM)
- [ ] XSS prevention (sanitization)
- [ ] CSRF protection (SameSite cookies)
- [ ] Helmet security headers
- [ ] Dependencies updated (npm audit)
- [ ] Secrets in environment variables

#### **Performance Checklist**
- [ ] Database indexes created
- [ ] Connection pooling configured
- [ ] Compression enabled
- [ ] Caching strategy implemented
- [ ] CDN for static assets
- [ ] Query optimization done
- [ ] N+1 queries eliminated

---

### 10.6 Monitoring & Maintenance

#### **Health Check Endpoint**
```typescript
app.get('/health', async (req, res) => {
  try {
    // Check database
    await sequelize.authenticate();
    
    // Check Redis (if using)
    await redisClient.ping();
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});
```

#### **Error Monitoring (Sentry)**
```typescript
import * as Sentry from '@sentry/node';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 1.0
});

// Error handler
app.use(Sentry.Handlers.errorHandler());
```

#### **Process Management (PM2)**
```javascript
// ecosystem.config.js
module.exports = {
  apps: [{
    name: 'spacedly-api',
    script: './dist/server.js',
    instances: 'max', // Use all CPU cores
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production'
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss'
  }]
};

// Start: pm2 start ecosystem.config.js
// Monitor: pm2 monit
// Restart: pm2 restart spacedly-api
```

---

### 10.7 Production Interview Questions

**Q1: How do you handle environment variables in production?**
**A:**
- Use `.env` files in development
- Use cloud provider's secret management (AWS Secrets Manager, Heroku Config Vars)
- Never commit `.env` to git
- Use strong secrets (32+ characters)
- Rotate secrets periodically

**Q2: What is the difference between development and production builds?**
**A:**
- **Development**: Source maps, verbose logging, auto-reload
- **Production**: Minified code, no source maps, error logging only, optimizations enabled

**Q3: How do you scale a Node.js application?**
**A:**
- **Vertical**: Increase server resources
- **Horizontal**: Multiple instances with load balancer
- **Clustering**: PM2 cluster mode (use all CPU cores)
- **Caching**: Redis for session/data
- **Database**: Read replicas, connection pooling
- **CDN**: Cloudinary for static assets

**Q4: What is zero-downtime deployment?**
**A:** Deploy new version without service interruption.

Strategies:
- Blue-green deployment
- Rolling updates
- Canary releases
- Load balancer health checks

**Q5: How do you monitor a production application?**
**A:**
- **Error tracking**: Sentry
- **Logging**: Winston, CloudWatch
- **Performance**: New Relic, DataDog
- **Uptime**: Pingdom, UptimeRobot
- **Metrics**: Prometheus, Grafana

---

## 11. Common Interview Questions

### Architecture & Design

**Q: Explain MVC vs Service-Controller architecture.**
**A:** Our architecture uses Service-Controller pattern:
- **Controllers**: Handle HTTP concerns (request/response)
- **Services**: Business logic, database operations
- **Models**: Data structure and validation
- **Routes**: URL mapping

Better than MVC because:
- Services are reusable across controllers
- Easier to test business logic
- Clear separation of concerns

**Q: How would you scale this application?**
**A:**
1. **Horizontal Scaling**: Multiple server instances with load balancer
2. **Database**: Read replicas, connection pooling
3. **Caching**: Redis for sessions and data
4. **CDN**: Cloudinary for static assets
5. **Queue**: BullMQ for background jobs
6. **Microservices**: Split into auth, task, notification services

**Q: What are the security best practices you implemented?**
**A:**
1. **Authentication**: JWT with refresh tokens, 2FA
2. **Authorization**: User-based access control
3. **Input validation**: Joi schemas
4. **Input sanitization**: XSS and NoSQL injection prevention
5. **Rate limiting**: Different limits for different routes
6. **Secure headers**: Helmet middleware
7. **CORS**: Whitelist allowed origins
8. **Password hashing**: bcrypt with salt
9. **HTTPS only**: In production
10. **httpOnly cookies**: Prevent XSS

### Node.js Specific

**Q: What is Event Loop in Node.js?**
**A:** Event Loop is the heart of Node.js that handles async operations:
1. **Call Stack**: Executes synchronous code
2. **Callback Queue**: Holds callbacks from async operations
3. **Event Loop**: Checks if call stack is empty, then pushes callbacks

Phases:
1. Timers (setTimeout, setInterval)
2. Pending callbacks
3. Idle, prepare
4. Poll (I/O operations)
5. Check (setImmediate)
6. Close callbacks

**Q: Difference between process.nextTick() and setImmediate()?**
**A:**
- `process.nextTick()`: Executes before next event loop phase
- `setImmediate()`: Executes in check phase of event loop

Use `process.nextTick()` for critical operations, `setImmediate()` for I/O.

**Q: What is middleware in Express?**
**A:** Functions that have access to req, res, next. They:
- Execute code
- Modify req/res
- End request-response cycle
- Call next middleware

Types:
- Application-level (app.use)
- Router-level (router.use)
- Error-handling (4 parameters)
- Built-in (express.json)
- Third-party (helmet, cors)

### Database & ORM

**Q: What is an ORM and why use Sequelize?**
**A:** ORM (Object-Relational Mapping) maps database tables to JavaScript objects.

Sequelize benefits:
- Write JavaScript instead of SQL
- Database agnostic (PostgreSQL, MySQL, SQLite)
- Migrations for version control
- Associations made easy
- Built-in validation
- Protection against SQL injection

**Q: What are database indexes and when to use them?**
**A:** Indexes speed up queries by creating a sorted data structure.

Use on:
- Foreign keys (user_id, task_id)
- Frequently queried columns (email, status)
- Columns in WHERE clauses
- Columns in ORDER BY

Don't overuse:
- Slow down INSERT/UPDATE
- Take up storage space

**Q: What is the N+1 problem?**
**A:** Making N additional queries when you could use 1 query with JOIN.

Solution: Eager loading with `include` in Sequelize.

### Testing

**Q: How would you test this application?**
**A:**
1. **Unit Tests**: Test individual functions (services)
2. **Integration Tests**: Test API endpoints
3. **E2E Tests**: Test complete user flows

Tools:
- Jest for unit/integration tests
- Supertest for API testing
- Postman/Newman for automated API tests

Example:
```typescript
describe('Task Service', () => {
  it('should create a task', async () => {
    const task = await taskService.createTask({
      userId: 'user-id',
      title: 'Test task'
    });
    expect(task.title).toBe('Test task');
  });
});
```

### Performance

**Q: How do you optimize database queries?**
**A:**
1. **Indexing**: Add indexes on frequently queried columns
2. **Eager loading**: Use `include` to avoid N+1
3. **Select specific fields**: `attributes: ['id', 'name']`
4. **Pagination**: Limit results with `limit` and `offset`
5. **Caching**: Cache frequently accessed data
6. **Connection pooling**: Reuse database connections

**Q: What is caching and when to use it?**
**A:** Storing computed results to avoid recalculation.

When to cache:
- Expensive database queries (analytics)
- Frequently accessed data (user profile)
- Rarely changing data (categories)

When NOT to cache:
- Real-time data (stock prices)
- User-specific sensitive data
- Frequently changing data

### Security

**Q: How do you prevent SQL injection?**
**A:**
1. **Parameterized queries**: Sequelize automatically escapes
2. **Input validation**: Joi schemas
3. **ORM**: Don't use raw queries
4. **Least privilege**: Database user has minimal permissions

**Q: Explain CORS and CSRF.**
**A:**
**CORS**: Controls which domains can access your API
- Set allowed origins
- Enable credentials for cookies

**CSRF**: Attack where malicious site makes requests on behalf of user
Prevention:
- SameSite cookies
- CSRF tokens
- Verify origin header

**Q: What is XSS and how to prevent it?**
**A:** XSS (Cross-Site Scripting): Injecting malicious scripts.

Types:
- Stored: Saved in database
- Reflected: In URL parameters
- DOM-based: In client-side JavaScript

Prevention:
- Input sanitization (remove script tags)
- Content Security Policy
- httpOnly cookies
- Encode output
- Validate input

### API Design

**Q: What are REST principles?**
**A:**
1. **Stateless**: Each request has all needed info
2. **Client-Server**: Separation of concerns
3. **Cacheable**: Responses can be cached
4. **Uniform Interface**: Consistent API design
5. **Layered System**: Can have intermediaries

HTTP Methods:
- GET: Retrieve data
- POST: Create data
- PUT: Update entire resource
- PATCH: Update partial resource
- DELETE: Remove data

**Q: How do you version APIs?**
**A:**
1. **URL versioning**: `/api/v1/users`
2. **Header versioning**: `Accept: application/vnd.api.v1+json`
3. **Query parameter**: `/api/users?version=1`

We use URL versioning (simplest, clearest).

### Error Handling

**Q: How do you handle errors in async code?**
**A:**
1. **Try-catch** in async functions
2. **asyncWrapper** to catch automatically
3. **Global error handler** for centralized handling
4. **Custom error classes** (ApiError)
5. **Proper HTTP status codes**

**Q: What HTTP status codes do you use?**
**A:**
- 200: Success
- 201: Created
- 400: Bad Request (validation error)
- 401: Unauthorized (not logged in)
- 403: Forbidden (no permission)
- 404: Not Found
- 429: Too Many Requests
- 500: Internal Server Error

---

## Additional Resources

### Project Setup
```bash
# Backend
cd backend
npm install
npx sequelize-cli db:migrate
npm run dev

# Frontend
cd frontend
npm install
npm run dev
```

### Environment Variables
```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/spacedly

# JWT
JWT_ACCESS_SECRET=your-access-secret
JWT_REFRESH_SECRET=your-refresh-secret

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Google OAuth
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/auth/google/callback

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Frontend URL
FRONTEND_URL=http://localhost:8080
```

### Key Packages
```json
{
  "express": "Web framework",
  "sequelize": "ORM for PostgreSQL",
  "jsonwebtoken": "JWT authentication",
  "bcryptjs": "Password hashing",
  "joi": "Input validation",
  "passport": "OAuth authentication",
  "multer": "File upload handling",
  "sharp": "Image optimization",
  "cloudinary": "Cloud storage",
  "nodemailer": "Email sending",
  "node-cron": "Scheduled tasks",
  "node-cache": "In-memory caching",
  "helmet": "Security headers",
  "express-rate-limit": "Rate limiting",
  "cors": "Cross-origin resource sharing"
}
```

---

## Summary

This backend application demonstrates:

1. **Authentication**: JWT with refresh tokens, 2FA, Google OAuth
2. **Security**: Multiple layers (rate limiting, input sanitization, CORS, helmet)
3. **File Management**: Cloudinary integration with Sharp optimization
4. **Task Management**: CRUD operations with associations
5. **Reminders**: Cron-based email system
6. **Notifications**: Real-time notification system
7. **Analytics**: Cached aggregated data with streak calculation
8. **Best Practices**: Service layer, error handling, validation, async patterns

**Key Technical Skills Demonstrated:**
- Node.js & TypeScript
- Express.js framework
- PostgreSQL with Sequelize ORM
- JWT authentication
- OAuth 2.0 integration
- File upload & optimization
- Email automation
- Cron jobs
- Caching strategies
- Security best practices
- RESTful API design

This documentation should prepare you for interviews by explaining not just what the code does, but **why** architectural decisions were made and **how** to scale and improve the system.

Good luck with your interview! 🚀
