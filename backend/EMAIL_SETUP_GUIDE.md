# Email Configuration Guide for Spacedly

## Problem: Email Sending Failures

If you're seeing errors like:
```
[Morning Email Error] Failed for reminder: Error: Connection timeout
  code: 'ETIMEDOUT',
  command: 'CONN'
```

This means the application cannot connect to Gmail's SMTP server. Here's how to fix it:

---

## Solution 1: Configure Gmail App Password (Recommended for Development)

### Prerequisites
- A Gmail account
- 2-Factor Authentication (2FA) enabled on your Google account

### Step-by-Step Setup

#### 1. Enable 2-Factor Authentication (if not already enabled)
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Under "Signing in to Google", click on "2-Step Verification"
3. Follow the prompts to set up 2FA

#### 2. Generate App Password
1. Visit [Google App Passwords](https://myaccount.google.com/apppasswords)
2. You may need to re-enter your Google password
3. In the "Select app" dropdown, choose "Mail"
4. In the "Select device" dropdown, choose "Other (Custom name)"
5. Enter a name like "Spacedly App"
6. Click "Generate"
7. **Copy the 16-character password** (it looks like: `abcd efgh ijkl mnop`)

#### 3. Configure Railway Environment Variables
1. Go to your Railway project dashboard
2. Select your backend service
3. Go to the "Variables" tab
4. Add/update these variables:
   ```
   EMAIL_USER=your-gmail@gmail.com
   EMAIL_PASS=abcdefghijklmnop  (the 16-char app password, no spaces)
   ```
5. Click "Deploy" or wait for auto-deployment

#### 4. Verify Setup
After deployment, check Railway logs:
- ✅ Should see: `✅ Email configuration detected`
- ❌ If you see: `⚠️ WARNING: Email variables not configured`
  - Double-check you set both EMAIL_USER and EMAIL_PASS
  - Ensure EMAIL_PASS is the App Password, not your regular password

---

## Solution 2: Use SendGrid (Recommended for Production)

For production applications, Gmail SMTP is not reliable. Use a dedicated email service:

### SendGrid Setup (Free Tier: 100 emails/day)

#### 1. Create SendGrid Account
1. Sign up at [SendGrid](https://signup.sendgrid.com/)
2. Verify your email address
3. Complete the "Tell us about yourself" form

#### 2. Create API Key
1. Go to Settings > [API Keys](https://app.sendgrid.com/settings/api_keys)
2. Click "Create API Key"
3. Name it "Spacedly Production"
4. Choose "Full Access" or "Restricted Access" (with Mail Send permissions)
5. Click "Create & View"
6. **Copy the API key** (you'll only see it once!)

#### 3. Verify Sender Identity
1. Go to Settings > [Sender Authentication](https://app.sendgine.com/settings/sender_auth)
2. Choose "Single Sender Verification" (easiest for small apps)
3. Enter your email address (the one you want emails to come from)
4. Verify the email by clicking the link sent to you

#### 4. Update Code for SendGrid

Install SendGrid package:
```bash
cd Spacedly/backend
yarn add @sendgrid/mail
```

Update `emailUtil.ts`:
```typescript
import sgMail from '@sendgrid/mail';
import dotenv from 'dotenv';
dotenv.config();

const USE_SENDGRID = process.env.SENDGRID_API_KEY && process.env.SENDGRID_FROM_EMAIL;

if (USE_SENDGRID) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY!);
}

export const sendEmail = async (
  to: string, 
  subject: string, 
  html: string, 
  retries = 3
): Promise<void> => {
  // If SendGrid is configured, use it
  if (USE_SENDGRID) {
    try {
      await sgMail.send({
        to,
        from: process.env.SENDGRID_FROM_EMAIL!,
        subject,
        html,
      });
      console.log(`[Email] Sent via SendGrid to ${to}`);
      return;
    } catch (error: any) {
      console.error('[SendGrid Error]:', error.response?.body || error.message);
      throw error;
    }
  }
  
  // Otherwise fall back to Gmail SMTP with retry logic
  // ... existing Gmail code ...
};
```

#### 5. Configure Railway Environment Variables
```
SENDGRID_API_KEY=your-sendgrid-api-key
SENDGRID_FROM_EMAIL=your-verified-email@example.com
```

---

## Troubleshooting

### Email still not sending after Gmail App Password setup?

1. **Check Railway logs for specific errors:**
   ```
   [Email] Attempt 1/3 failed: <error message>
   ```

2. **Common issues:**
   - **"Invalid login"**: You used regular password instead of App Password
   - **"ETIMEDOUT"**: Gmail may be blocking Railway's IP
     - Solution: Switch to SendGrid
   - **"Username and Password not accepted"**: 
     - Ensure 2FA is enabled
     - Generate a new App Password
     - Remove spaces from the App Password in environment variables

3. **Verify environment variables in Railway:**
   - Go to Variables tab
   - Check EMAIL_USER and EMAIL_PASS are set correctly
   - No extra spaces or quotes

4. **Test locally first:**
   ```bash
   cd Spacedly/backend
   # Create .env file with your email credentials
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-password
   
   # Run the server
   yarn dev
   ```

### Gmail Security Concerns

If Gmail blocks the connection:
1. Check [Recent Security Activity](https://myaccount.google.com/notifications)
2. If you see "Blocked sign-in attempt", you may need to:
   - Use a different email provider
   - Switch to SendGrid (recommended)

---

## Best Practices

### For Development
✅ Gmail with App Password is fine
✅ Keep credentials in environment variables
✅ Never commit credentials to git

### For Production
✅ Use dedicated email service (SendGrid, AWS SES, Mailgun)
✅ Set up SPF/DKIM/DMARC records for better deliverability
✅ Monitor email sending metrics
✅ Implement retry logic with exponential backoff (already added)
✅ Add email queuing for high volume

---

## Quick Reference

### Current Implementation Features
- ✅ Automatic retry with exponential backoff (3 attempts)
- ✅ Connection timeout handling (10s connection, 15s socket)
- ✅ Connection pooling for better performance
- ✅ Detailed error logging
- ✅ Environment variable validation on startup

### Environment Variables Required
```bash
# Required for email functionality
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-16-char-app-password

# Optional (for SendGrid)
SENDGRID_API_KEY=SG.xxxxxxxxxxxxx
SENDGRID_FROM_EMAIL=verified-sender@example.com
```

---

## Support

If you continue to have issues:
1. Check Railway deployment logs for specific error messages
2. Verify your environment variables are set correctly
3. Try sending a test email from Railway console
4. Consider switching to SendGrid for production use

For Gmail App Password issues, visit:
- [Google App Passwords Help](https://support.google.com/accounts/answer/185833)
- [2-Step Verification Help](https://support.google.com/accounts/answer/185839)
