# 🚀 Railway Deployment Quick Checklist

Quick reference checklist for deploying Spacedly backend to Railway.

---

## Pre-Deployment Setup

### Local Testing
```bash
cd backend
npm run build
npm run start:prod
```

✅ Build completes without errors  
✅ Server starts on production mode  
✅ All tests pass (if applicable)

---

## Railway Account Setup

1. Go to https://railway.app
2. Sign up with GitHub
3. Authorize Railway

✅ Railway account created  
✅ GitHub connected

---

## Create Railway Project

1. Click "New Project"
2. Choose "Deploy from GitHub repo"
3. Select `Spacedly` repository
4. Set **Root Directory**: `backend`

✅ Project created  
✅ Root directory configured

---

## Add PostgreSQL Database

1. Click "+ New" in project
2. Select "Database" → "PostgreSQL"

✅ PostgreSQL service added  
✅ Database credentials available

---

## Environment Variables

Copy and paste these into Railway Variables tab (update values):

### Required Variables

```bash
# Application
NODE_ENV=production
PORT=3000

# Database (Auto-provided by Railway)
DATABASE_URL=${{Postgres.DATABASE_URL}}

# JWT Secrets (Generate new ones!)
JWT_ACCESS_SECRET=your-64-char-secret-here
JWT_REFRESH_SECRET=your-64-char-secret-here

# Frontend (Update after frontend deployment)
FRONTEND_URL=https://your-frontend.vercel.app
ALLOWED_ORIGINS=https://your-frontend.vercel.app

# Email (Gmail)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-gmail-app-password
EMAIL_FROM=your-email@gmail.com

# Google OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_CALLBACK_URL=https://your-backend.railway.app/api/auth/google/callback

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```

### Generate JWT Secrets

Run locally:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

✅ All variables added  
✅ JWT secrets generated  
✅ Email configured  
✅ OAuth configured  
✅ Cloudinary configured

---

## Deploy

1. Go to "Deployments" tab
2. Click "Deploy"
3. Wait 3-5 minutes
4. Check build logs

✅ Deployment successful  
✅ No build errors  
✅ Migrations ran

---

## Generate Domain

1. Go to "Settings" tab
2. Scroll to "Networking"
3. Click "Generate Domain"
4. Copy URL: `https://your-project.railway.app`

✅ Domain generated  
✅ URL copied

---

## Test Deployment

```bash
# Replace with your Railway URL
curl https://your-project.railway.app/health
```

Expected response:
```json
{"status":"healthy","timestamp":"...","uptime":123}
```

✅ Health endpoint works  
✅ Backend is live

---

## Update Google OAuth

1. Go to Google Cloud Console
2. APIs & Services → Credentials
3. Add redirect URI:
   ```
   https://your-project.railway.app/api/auth/google/callback
   ```

✅ OAuth redirect updated

---

## Update Railway Variables

Update these with your actual Railway URL:

```bash
GOOGLE_CALLBACK_URL=https://your-project.railway.app/api/auth/google/callback
```

✅ Callback URL updated  
✅ Service restarted

---

## Test Endpoints

### Test Signup
```bash
curl -X POST https://your-project.railway.app/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "password": "Test@123456"
  }'
```

### Test Login
```bash
curl -X POST https://your-project.railway.app/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test@123456"
  }'
```

✅ Signup works  
✅ Login works  
✅ OTP email sent

---

## Verify Database

1. Go to PostgreSQL service
2. Click "Data" tab
3. Check tables exist:
   - users
   - tasks
   - reminders
   - notifications
   - task_attachments

✅ All tables created  
✅ Migrations successful

---

## Update Frontend

In your frontend `.env`:

```bash
VITE_API_URL=https://your-project.railway.app
```

Then redeploy frontend.

✅ Frontend updated  
✅ Frontend deployed

---

## Final Testing

Test these features end-to-end:

- [ ] Signup with email
- [ ] Verify OTP
- [ ] Login
- [ ] Google OAuth login
- [ ] Create task
- [ ] Upload attachment
- [ ] Set reminder
- [ ] Receive email notification
- [ ] View analytics
- [ ] Update profile
- [ ] Upload profile picture

✅ All features working  
✅ Production ready

---

## Security Checklist

- [ ] Changed all default passwords
- [ ] Generated new JWT secrets (64+ chars)
- [ ] HTTPS enabled (automatic on Railway)
- [ ] CORS configured properly
- [ ] Rate limiting enabled
- [ ] Security headers enabled
- [ ] Environment variables secure
- [ ] No secrets in Git
- [ ] 2FA on Railway account

✅ All security measures in place

---

## Troubleshooting

### Build Fails
1. Check deployment logs
2. Verify all dependencies in `package.json`
3. Test `npm run build` locally

### Database Connection Error
1. Verify `DATABASE_URL` is set
2. Check PostgreSQL service is running
3. Look at service logs

### CORS Errors
1. Update `ALLOWED_ORIGINS` with frontend URL
2. Include both production and localhost
3. Restart service

### 502 Bad Gateway
1. Check server started successfully
2. Verify `PORT` uses `process.env.PORT`
3. Look for startup errors in logs

---

## Support Resources

- Railway Docs: https://docs.railway.app
- Railway Discord: https://discord.gg/railway
- Deployment Guide: See `RAILWAY_DEPLOYMENT_GUIDE.md`

---

## Deployment Complete! 🎉

Your backend is live at:
```
https://your-project.railway.app
```

Next steps:
1. ✅ Share with team
2. ✅ Add to resume
3. ✅ Show to employers
4. ✅ Monitor logs regularly

---

**Last Updated**: December 6, 2024
