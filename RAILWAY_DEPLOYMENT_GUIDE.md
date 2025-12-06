# 🚀 Railway Deployment Guide - Spacedly Backend

Complete step-by-step guide to deploy your Spacedly backend to Railway.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Project Preparation](#project-preparation)
3. [Railway Setup](#railway-setup)
4. [Database Configuration](#database-configuration)
5. [Environment Variables](#environment-variables)
6. [Deployment](#deployment)
7. [Post-Deployment](#post-deployment)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, ensure you have:

- ✅ **GitHub Account** - Your code should be in a GitHub repository
- ✅ **Railway Account** - Sign up at [railway.app](https://railway.app)
- ✅ **Domain Access** - For Google OAuth callbacks (optional initially)
- ✅ **Cloudinary Account** - For image uploads
- ✅ **Gmail App Password** - For sending emails (or SendGrid)

---

## Project Preparation

### Files Created

The following files have been created for Railway deployment:

1. **`railway.json`** - Railway configuration
2. **`.railwayignore`** - Files to ignore during deployment
3. **Updated `package.json`** - Added production scripts

### Verify TypeScript Configuration

Ensure your `tsconfig.json` includes:

```json
{
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src"
  }
}
```

### Test Local Build

Before deploying, test the build locally:

```bash
cd backend
npm run build
npm run start:prod
```

If this works locally, it will work on Railway!

---

## Railway Setup

### Step 1: Create Railway Account

1. Go to [railway.app](https://railway.app)
2. Click **"Login"**
3. Choose **"Login with GitHub"** (recommended)
4. Authorize Railway to access your repositories

### Step 2: Create New Project

1. From Railway dashboard, click **"New Project"**
2. Select **"Deploy from GitHub repo"**
3. Choose your **Spacedly** repository
4. Railway will automatically detect it's a Node.js project

### Step 3: Configure Root Directory

Since your backend is in a subfolder:

1. Click on the deployed service
2. Go to **"Settings"** tab
3. Scroll to **"Root Directory"**
4. Enter: `backend`
5. Click **"Save"**

### Step 4: Verify Build Configuration

Railway should auto-detect, but verify:

- **Build Command**: `npm install && npm run build`
- **Start Command**: `npm run start:prod`

These are already configured in `railway.json` and `package.json`.

---

## Database Configuration

### Step 1: Add PostgreSQL Database

1. In your Railway project dashboard
2. Click **"+ New"** button
3. Select **"Database"**
4. Choose **"Add PostgreSQL"**
5. Railway creates a PostgreSQL instance automatically

### Step 2: Connect Database to Service

Railway automatically connects services in the same project. The database URL will be available as `DATABASE_URL`.

### Step 3: Get Database Credentials

1. Click on the **PostgreSQL** service
2. Go to **"Variables"** tab
3. You'll see:
   - `POSTGRES_USER`
   - `POSTGRES_PASSWORD`
   - `POSTGRES_DB`
   - `DATABASE_URL` (formatted connection string)

**Note**: You don't need to copy these manually - Railway provides them via environment variables.

---

## Environment Variables

### Step 1: Access Variables Configuration

1. Click on your **backend service** (not the database)
2. Go to **"Variables"** tab
3. Click **"+ New Variable"**

### Step 2: Add Required Variables

Add each of these variables one by one:

#### Application Settings

```bash
NODE_ENV=production
PORT=3000
```

#### Database (Auto-provided by Railway)

```bash
# Railway automatically provides this when you add PostgreSQL
# You can reference it like this:
DATABASE_URL=${{Postgres.DATABASE_URL}}
```

**Note**: Railway uses `${{Postgres.DATABASE_URL}}` syntax to reference other service variables.

#### JWT Secrets (IMPORTANT: Generate New Ones!)

**Generate secure secrets:**

```bash
# Run these commands locally to generate random secrets:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

Then add:

```bash
JWT_ACCESS_SECRET=<paste-first-generated-secret>
JWT_REFRESH_SECRET=<paste-second-generated-secret>
```

#### CORS & Frontend

```bash
# Update this after deploying frontend
FRONTEND_URL=https://your-frontend-url.vercel.app
ALLOWED_ORIGINS=https://your-frontend-url.vercel.app
```

**Note**: For now, you can use a placeholder. Update after frontend deployment.

#### Email Configuration (Gmail)

If using Gmail:

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-gmail-app-password
EMAIL_FROM=your-email@gmail.com
```

**How to get Gmail App Password:**

1. Go to Google Account Settings
2. Security → 2-Step Verification (enable if not already)
3. App Passwords → Generate new app password
4. Select "Mail" and "Other (Custom name)"
5. Copy the 16-character password

#### Google OAuth

```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_CALLBACK_URL=https://your-backend-url.railway.app/api/auth/google/callback
```

**Note**: Update `GOOGLE_CALLBACK_URL` after getting your Railway domain.

#### Cloudinary

```bash
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```

**Get these from**: [cloudinary.com](https://cloudinary.com) → Dashboard → API Keys

### Step 3: Verify All Variables

Double-check you've added:

- [ ] NODE_ENV
- [ ] PORT
- [ ] DATABASE_URL (or reference to Postgres)
- [ ] JWT_ACCESS_SECRET
- [ ] JWT_REFRESH_SECRET
- [ ] FRONTEND_URL
- [ ] ALLOWED_ORIGINS
- [ ] SMTP_* (all email variables)
- [ ] GOOGLE_* (all OAuth variables)
- [ ] CLOUDINARY_* (all cloudinary variables)

---

## Deployment

### Step 1: Trigger Deployment

Railway auto-deploys when you push to GitHub. Or manually:

1. Go to **"Deployments"** tab
2. Click **"Deploy"** or **"Redeploy"**
3. Watch the build logs in real-time

### Step 2: Monitor Build Progress

The build process will:

1. Clone your repository
2. Install dependencies (`npm install`)
3. Build TypeScript (`npm run build`)
4. Run migrations (`postbuild` script)
5. Start the server (`npm run start:prod`)

**Expected time**: 3-5 minutes

### Step 3: Check Build Logs

If deployment fails:

1. Click on the failed deployment
2. Read the logs carefully
3. Common issues:
   - Missing dependencies
   - TypeScript compilation errors
   - Environment variable issues

### Step 4: Generate Domain

Once deployed successfully:

1. Go to **"Settings"** tab
2. Scroll to **"Networking"** section
3. Click **"Generate Domain"**
4. Your backend will be at: `https://your-project-name.railway.app`

**Copy this URL** - you'll need it for:
- Frontend configuration
- Google OAuth callback
- Testing

---

## Post-Deployment

### Step 1: Verify Deployment

Test your backend is running:

```bash
# Replace with your actual Railway URL
curl https://your-project-name.railway.app/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-12-06T...",
  "uptime": 123.45
}
```

### Step 2: Test Authentication Endpoints

```bash
# Test signup endpoint
curl -X POST https://your-project-name.railway.app/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "password": "Test@123456"
  }'
```

### Step 3: Verify Database Migrations

Check if tables were created:

1. Go to PostgreSQL service
2. Click **"Data"** tab
3. You should see tables: `users`, `tasks`, `reminders`, `notifications`, etc.

### Step 4: Update Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Navigate to your project
3. APIs & Services → Credentials
4. Edit your OAuth 2.0 Client ID
5. Add to **Authorized redirect URIs**:
   ```
   https://your-project-name.railway.app/api/auth/google/callback
   ```
6. Save

### Step 5: Update Railway Environment Variables

Now that you have your backend URL:

1. Go to Railway → Variables
2. Update:
   ```bash
   GOOGLE_CALLBACK_URL=https://your-project-name.railway.app/api/auth/google/callback
   ```
3. The service will auto-restart

### Step 6: Update Frontend Configuration

In your frontend repository, update `.env`:

```bash
VITE_API_URL=https://your-project-name.railway.app
```

Then deploy/redeploy your frontend.

---

## Troubleshooting

### Issue 1: Build Fails

**Symptoms**: Deployment fails during build phase

**Solutions**:

1. **Check dependencies**:
   ```bash
   # Ensure all dependencies are in package.json, not devDependencies
   # Railway runs: npm install --production
   ```

2. **Verify TypeScript compiles locally**:
   ```bash
   cd backend
   npm run build
   ```

3. **Check build logs** for specific errors

### Issue 2: Database Connection Error

**Symptoms**: 
```
Error: connect ECONNREFUSED
SequelizeConnectionError
```

**Solutions**:

1. **Verify DATABASE_URL is set**:
   - Check Variables tab
   - Should be: `${{Postgres.DATABASE_URL}}`

2. **Check database is running**:
   - PostgreSQL service should show "Active"

3. **Verify database configuration** in `config/database.ts`:
   ```typescript
   // Should use process.env.DATABASE_URL
   ```

### Issue 3: Port Binding Error

**Symptoms**:
```
Error: listen EADDRINUSE :::3000
```

**Solutions**:

Ensure your server uses Railway's assigned port:

```typescript
// In server.ts
const PORT = process.env.PORT || 3000;
```

Railway dynamically assigns a port - your app must listen on `process.env.PORT`.

### Issue 4: CORS Errors

**Symptoms**:
```
Access to fetch at '...' has been blocked by CORS policy
```

**Solutions**:

1. **Update ALLOWED_ORIGINS**:
   ```bash
   ALLOWED_ORIGINS=https://your-frontend-url.vercel.app,http://localhost:5173
   ```

2. **Verify CORS configuration** in `app.ts`

### Issue 5: Migrations Don't Run

**Symptoms**: Tables not created in database

**Solutions**:

1. **Check if postbuild script ran**:
   - Look in deployment logs for "npm run migrate"

2. **Manually run migrations**:
   ```bash
   # Using Railway CLI
   railway run npm run migrate
   ```

3. **Verify `.sequelizerc` configuration**:
   ```javascript
   // Should point to correct paths
   ```

### Issue 6: Environment Variables Not Loading

**Symptoms**: `undefined` for environment variables

**Solutions**:

1. **Check variable names** (case-sensitive)
2. **Restart service** after adding variables
3. **Verify .env loading** in code:
   ```typescript
   import dotenv from 'dotenv';
   dotenv.config();
   ```

### Issue 7: 502 Bad Gateway

**Symptoms**: Railway shows "502 Bad Gateway"

**Solutions**:

1. **Check if server started successfully**:
   - Look in logs for "Server running on port..."

2. **Verify start command**:
   - Should be `npm run start:prod`
   - Should run `node dist/server.js`

3. **Check for startup errors** in logs

---

## Monitoring & Maintenance

### View Logs

Real-time application logs:

1. Go to your service
2. Click **"Logs"** tab
3. See live logs as they happen

**Tip**: Use logs to debug issues in production.

### Metrics

View resource usage:

1. Click **"Metrics"** tab
2. See:
   - CPU usage
   - Memory usage
   - Network traffic

### Deployments History

View previous deployments:

1. Go to **"Deployments"** tab
2. See all deployment attempts
3. Rollback if needed: Click **"Redeploy"** on a previous successful deployment

---

## Railway CLI (Advanced)

For advanced users who prefer CLI:

### Install Railway CLI

```bash
npm install -g @railway/cli
```

### Login

```bash
railway login
```

### Link Project

```bash
cd backend
railway link
```

### Deploy from CLI

```bash
railway up
```

### Run Commands

```bash
# Run migrations
railway run npm run migrate

# Open logs
railway logs

# Open project in browser
railway open

# Set environment variables
railway variables set KEY=value
```

---

## Pricing Information

### Free Tier

Railway offers $5/month in credits (as of 2024):

- **Resources**: Enough for small projects
- **Sleep Mode**: Services sleep after 30 min inactivity
- **Database**: 1GB PostgreSQL included

**Cost Estimate for Spacedly**:
- Backend: ~$2-3/month
- PostgreSQL: ~$1-2/month
- **Total**: ~$3-5/month (within free tier!)

### Hobby Plan

If you exceed free tier:

- **Cost**: $5/month
- **No Sleep**: Services always active
- **More Resources**: Higher limits

---

## Security Checklist

Before going to production:

- [ ] Changed all default secrets and passwords
- [ ] Generated new strong JWT secrets (64+ characters)
- [ ] Set up HTTPS (Railway does this automatically)
- [ ] Configured CORS properly
- [ ] Enabled rate limiting (already in code)
- [ ] Set secure cookie options (already in code)
- [ ] Added Helmet security headers (already in code)
- [ ] Don't commit `.env` file to Git
- [ ] Use environment variables for all secrets
- [ ] Enable 2FA on your Railway account

---

## Useful Commands

### Local Testing

```bash
# Build
npm run build

# Test production build locally
npm run start:prod

# Run migrations
npm run migrate

# Undo last migration
npm run migrate:undo
```

### Railway CLI

```bash
# View logs
railway logs

# Run one-off command
railway run <command>

# Open shell
railway shell

# Set variables
railway variables set KEY=value

# Get variables
railway variables
```

---

## Next Steps

After successful deployment:

1. ✅ Deploy frontend to Vercel/Netlify
2. ✅ Update frontend API URL
3. ✅ Test all features end-to-end
4. ✅ Set up custom domain (optional)
5. ✅ Configure monitoring/alerts
6. ✅ Set up CI/CD pipeline (optional)

---

## Support & Resources

- **Railway Docs**: https://docs.railway.app
- **Railway Discord**: https://discord.gg/railway
- **Railway Status**: https://status.railway.app
- **Pricing**: https://railway.app/pricing

---

## Deployment Checklist

Use this checklist to ensure everything is set up:

### Pre-Deployment

- [ ] Code is in GitHub repository
- [ ] All dependencies in `package.json`
- [ ] `.env.example` file updated with all required variables
- [ ] TypeScript compiles without errors (`npm run build`)
- [ ] App runs locally with production build (`npm run start:prod`)

### Railway Setup

- [ ] Created Railway account
- [ ] Created new project from GitHub
- [ ] Set root directory to `backend`
- [ ] Added PostgreSQL database
- [ ] All environment variables configured
- [ ] Generated strong JWT secrets
- [ ] Domain generated

### Post-Deployment

- [ ] Health endpoint responding
- [ ] Database migrations ran successfully
- [ ] All tables created
- [ ] Can create user (test signup)
- [ ] Can login
- [ ] Google OAuth configured
- [ ] Email sending works
- [ ] File uploads work (Cloudinary)
- [ ] Frontend can connect to backend
- [ ] CORS configured correctly

### Production Ready

- [ ] All secrets rotated from defaults
- [ ] Security headers enabled
- [ ] Rate limiting active
- [ ] Monitoring set up
- [ ] Error logging configured
- [ ] Backup strategy in place

---

## Congratulations! 🎉

Your Spacedly backend is now deployed to Railway!

Backend URL: `https://your-project-name.railway.app`

You can now:
- Access your API endpoints
- Connect your frontend
- Use all features in production
- Show it to potential employers! 💼

---

**Created**: December 6, 2024  
**Author**: Spacedly Development Team  
**Version**: 1.0.0
