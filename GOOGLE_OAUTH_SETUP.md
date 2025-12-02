# Google OAuth Implementation Guide

## 🎯 Overview

This guide explains the Google OAuth implementation in Spacedly and how to configure it.

## 📋 What Was Implemented

### Backend Changes

1. **Database Schema Updates**
   - Added `google_id` field (stores Google user ID)
   - Added `auth_provider` field (enum: 'local' | 'google')
   - Made `password` field nullable (Google users don't need passwords)
   - Migration file: `backend/src/migrations/20251202070000-add-google-auth-fields.js`

2. **Passport.js Integration**
   - Installed packages: `passport`, `passport-google-oauth20`
   - Configuration: `backend/src/config/passport.ts`
   - Handles user creation and account linking

3. **Auth Routes**
   - `GET /api/auth/google` - Initiates OAuth flow
   - `GET /api/auth/google/callback` - Handles Google callback
   - File: `backend/src/routes/auth.routes.ts`

4. **CORS Configuration**
   - Updated `backend/src/app.ts` to allow OAuth redirects
   - Set `sameSite: 'lax'` for cookies (required for OAuth)

### Frontend Changes

Both Login and Signup pages already include:
- Google login button with official Google icon
- Click handler that redirects to `/api/auth/google`
- Proper error handling

## 🔧 Setup Instructions

### Step 1: Google Cloud Console Setup

1. **Go to Google Cloud Console**
   - Visit: https://console.cloud.google.com/

2. **Create a New Project** (or use existing)
   - Click "Select a project" → "New Project"
   - Name: "Spacedly" (or your choice)
   - Click "Create"

3. **Enable Google+ API**
   - Go to "APIs & Services" → "Library"
   - Search for "Google+ API"
   - Click "Enable"

4. **Configure OAuth Consent Screen**
   - Go to "APIs & Services" → "OAuth consent screen"
   - Choose "External" → Click "Create"
   - Fill in required fields:
     - App name: **Spacedly**
     - User support email: your email
     - Developer contact: your email
   - Click "Save and Continue"
   - Scopes: Click "Add or Remove Scopes"
     - Add: `userinfo.email`
     - Add: `userinfo.profile`
   - Click "Save and Continue"
   - Test users (optional during development)
   - Click "Save and Continue"

5. **Create OAuth 2.0 Credentials**
   - Go to "APIs & Services" → "Credentials"
   - Click "+ Create Credentials" → "OAuth client ID"
   - Application type: **Web application**
   - Name: "Spacedly Web Client"
   - **Authorized JavaScript origins:**
     - Development: `http://localhost:5173`
     - Production: `https://yourdomain.com`
   - **Authorized redirect URIs:**
     - Development: `http://localhost:5000/api/auth/google/callback`
     - Production: `https://api.yourdomain.com/api/auth/google/callback`
   - Click "Create"
   - **Save the Client ID and Client Secret!**

### Step 2: Configure Environment Variables

#### Backend (.env)

Add these variables to `backend/.env`:

```env
# Google OAuth
GOOGLE_CLIENT_ID=your_client_id_here.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret_here
GOOGLE_CALLBACK_URL=http://localhost:5000/api/auth/google/callback

# Frontend URL (for redirects)
FRONTEND_URL=http://localhost:5173

# Database (ensure these are set)
DB_USERNAME=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=your_db_name
DB_HOST=localhost
DB_DIALECT=postgres

# JWT Secrets (ensure these are set)
JWT_ACCESS_SECRET=your_access_secret
JWT_REFRESH_SECRET=your_refresh_secret

# Email (for OTP)
EMAIL_USER=your_gmail@gmail.com
EMAIL_PASS=your_app_password

# Node Environment
NODE_ENV=development
```

#### Frontend (.env)

Ensure `frontend/.env` has:

```env
VITE_API_BASE_URL=http://localhost:5000/api
```

### Step 3: Run Database Migration

```bash
cd backend
npx sequelize-cli db:migrate
```

This will add the `google_id` and `auth_provider` columns to your users table.

### Step 4: Start the Application

**Backend:**
```bash
cd backend
npm run dev
```

**Frontend:**
```bash
cd frontend
npm run dev
```

## 🔄 How It Works

### User Flow

```
1. User clicks "Sign in with Google" button
   ↓
2. Frontend redirects to: http://localhost:5000/api/auth/google
   ↓
3. Backend (Passport) redirects to Google consent screen
   ↓
4. User approves on Google
   ↓
5. Google redirects to: http://localhost:5000/api/auth/google/callback?code=...
   ↓
6. Backend exchanges code for user profile
   ↓
7. Backend creates/finds user in database
   ↓
8. Backend generates JWT tokens
   ↓
9. Backend sets cookies and redirects to: http://localhost:5173/dashboard
   ↓
10. User is logged in! ✅
```

### Account Linking Logic

The implementation handles three scenarios:

1. **New Google User**
   - Creates new user with Google profile
   - No password required
   - `auth_provider = 'google'`

2. **Existing Email (Local Account)**
   - Links Google account to existing user
   - Updates `google_id` and `auth_provider`
   - User can now login via Google OR email/password

3. **Returning Google User**
   - Finds user by `google_id`
   - Generates tokens and logs in

## 🔒 Security Features

- ✅ JWT tokens (15 min access, 30 day refresh)
- ✅ httpOnly cookies (XSS protection)
- ✅ CORS configured properly
- ✅ Google handles email verification
- ✅ Secure OAuth 2.0 flow
- ✅ State parameter (CSRF protection via Passport)

## 🧪 Testing

1. **Development Testing:**
   - Use any Google account
   - No need to publish the app
   - Works on localhost

2. **Add Test Users** (optional):
   - In Google Cloud Console
   - Go to OAuth consent screen
   - Add test user emails

3. **Test Scenarios:**
   - Sign up with new Google account
   - Sign in with existing Google account
   - Link Google to existing email account

## 🚀 Production Deployment

### Update Environment Variables:

**Backend:**
```env
GOOGLE_CALLBACK_URL=https://api.yourdomain.com/api/auth/google/callback
FRONTEND_URL=https://yourdomain.com
NODE_ENV=production
```

**Frontend:**
```env
VITE_API_BASE_URL=https://api.yourdomain.com/api
```

### Update Google Console:

1. Add production URLs to authorized origins
2. Add production callback URL
3. Publish OAuth consent screen (if needed)

## 📝 API Endpoints

### Initiate Google OAuth
```
GET /api/auth/google
```
Redirects user to Google consent screen.

### Google Callback
```
GET /api/auth/google/callback
```
Handles Google's response and logs user in.

## 🐛 Troubleshooting

### "redirect_uri_mismatch" Error
- Check that callback URL in code matches Google Console
- Ensure no trailing slashes
- Verify http vs https

### "Cookies not being set"
- Check CORS configuration
- Verify `credentials: true` in CORS
- Ensure `sameSite: 'lax'` in cookie options

### "User not found after OAuth"
- Check database connection
- Verify migration ran successfully
- Check Passport configuration

### "Cannot find module 'passport'"
- Run: `cd backend && npm install`
- Ensure all packages installed

## 🎓 Additional Features to Consider

1. **2FA for Google Users**
   - Currently Google users skip 2FA
   - Consider implementing Google Authenticator

2. **Logout Endpoint**
   - Add `/api/auth/logout` to clear cookies

3. **Account Unlinking**
   - Allow users to unlink Google account

4. **Multiple OAuth Providers**
   - Add GitHub, Facebook, etc.

## 📚 Resources

- [Passport.js Documentation](http://www.passportjs.org/)
- [Google OAuth 2.0 Guide](https://developers.google.com/identity/protocols/oauth2)
- [Google Cloud Console](https://console.cloud.google.com/)

## ✅ Checklist

- [ ] Create Google Cloud project
- [ ] Configure OAuth consent screen
- [ ] Create OAuth 2.0 credentials
- [ ] Add environment variables
- [ ] Run database migration
- [ ] Test login flow
- [ ] Test signup flow
- [ ] Test account linking
- [ ] Update for production

---

**Need help?** Check the troubleshooting section or review the implementation files:
- `backend/src/config/passport.ts`
- `backend/src/routes/auth.routes.ts`
- `frontend/src/pages/Login.tsx`
- `frontend/src/pages/Signup.tsx`
