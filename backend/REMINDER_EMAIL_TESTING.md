# Reminder Email System - Testing Guide

## 🎉 System Overview

The reminder email system automatically sends:
1. **Morning Email (5 AM IST)**: Sent for all tasks scheduled today
2. **1-Hour Before Email**: Sent 1 hour before the scheduled reminder time

## 📋 Prerequisites

1. ✅ Backend server running (`npm run dev`)
2. ✅ Valid Gmail credentials in `.env`:
   ```
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-password
   ```
3. ✅ Database migrated (already done!)

## 🧪 Testing Methods

### Method 1: Quick Test with Manual Endpoints (RECOMMENDED)

These endpoints let you test immediately without waiting:

#### Test Morning Reminders
```bash
POST http://localhost:5000/api/reminders/test/morning-reminders
Authorization: Bearer YOUR_TOKEN
```

This will:
- Find all reminders scheduled for today
- Send morning emails immediately
- Return count of emails sent

#### Test 1-Hour Before Reminders
```bash
POST http://localhost:5000/api/reminders/test/hour-before-reminders
Authorization: Bearer YOUR_TOKEN
```

This will:
- Find all reminders scheduled 1 hour from now (±5 min buffer)
- Send 1-hour-before emails immediately
- Return count of emails sent

### Method 2: Real-World Test with Actual Scheduling

1. **Create a task with a reminder 1 hour from now**:
   - Go to Tasks page
   - Click "New Task"
   - Fill in task details
   - Add a reminder for 1 hour from current time
   - Create the task

2. **Keep backend running**:
   ```bash
   cd backend
   npm run dev
   ```

3. **Wait and watch**:
   - Check terminal logs every hour
   - Email should arrive 1 hour before scheduled time
   - Check your email inbox

4. **For 5 AM test**:
   - Create a task for tomorrow with any time
   - Keep server running overnight
   - Check email at 5 AM IST

## 📊 What to Look For

### Terminal Logs
```
✅ Reminder cron job started - Running every hour
   - Morning emails: 5:00 AM IST (11:30 PM UTC)
   - 1-hour-before emails: Every hour

[Cron] Running reminder checks at 2025-12-03T16:30:00.000Z
[Cron] Checking for 1-hour-before reminders...
[1-Hour Reminders] Found 2 reminders to send
[1-Hour Email] Sent to user@example.com for task: Complete Report
[Cron] 1-hour-before reminders sent: 2
```

### Email Content

#### Morning Email (5 AM)
- Subject: "🌅 Good Morning - Your Task Reminder"
- Shows task title and description
- Displays scheduled time in IST
- Clean, branded design

#### 1-Hour Before Email
- Subject: "⏰ Task Starting in 1 Hour!"
- Urgent styling with countdown
- Task details
- IST time display

## 🐛 Troubleshooting

### No Emails Sent?

1. **Check email credentials**:
   ```bash
   # In backend/.env
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-16-char-app-password  # Not regular password!
   ```

2. **Check terminal for errors**:
   - Look for `[Morning Email Error]` or `[1-Hour Email Error]`
   - Common: Gmail authentication issues

3. **Check database**:
   ```sql
   SELECT * FROM reminders WHERE status = 'pending';
   ```

4. **Check timezone**:
   - Cron runs in UTC
   - Emails show IST time
   - Database stores UTC

### Emails Going to Spam?

- Check spam folder
- Add sender to contacts
- Mark as "Not Spam"

### Cron Not Running?

1. **Check if server started properly**:
   ```
   ✅ Reminder cron job started - Running every hour
   ```

2. **Check for errors in startup**:
   ```
   [Cron Error]: ...
   ```

## 🎯 Test Scenarios

### Scenario 1: Same-Day Task
1. Create task for 2 hours from now
2. Use manual endpoint to test immediately
3. Verify email received

### Scenario 2: Tomorrow's Task
1. Create task for tomorrow 10 AM
2. Check for morning email at 5 AM tomorrow
3. Check for 1-hour email at 9 AM tomorrow

### Scenario 3: Multiple Tasks
1. Create 3 tasks for different times today
2. Trigger morning reminders endpoint
3. Should receive 3 emails

## 📝 API Testing with Postman/Insomnia

### 1. Login First
```json
POST http://localhost:5000/api/auth/login
{
  "email": "your@email.com",
  "password": "yourpassword"
}
```
Save the `accessToken` from response.

### 2. Test Morning Reminders
```json
POST http://localhost:5000/api/reminders/test/morning-reminders
Headers:
  Authorization: Bearer YOUR_ACCESS_TOKEN
```

### 3. Test 1-Hour Before Reminders
```json
POST http://localhost:5000/api/reminders/test/hour-before-reminders
Headers:
  Authorization: Bearer YOUR_ACCESS_TOKEN
```

## ✅ Success Indicators

- [ ] Cron job starts on server boot
- [ ] Terminal shows hourly checks
- [ ] Morning endpoint sends emails for today's tasks
- [ ] 1-hour endpoint sends for upcoming tasks
- [ ] Emails have correct IST times
- [ ] Database flags `morning_email_sent` and `hour_before_email_sent`
- [ ] No duplicate emails sent

## 🚀 Production Deployment

When deploying to production:
1. Server stays running 24/7 (unlike local)
2. Cron automatically runs every hour
3. No manual triggering needed
4. Emails send automatically at correct times

## 📧 Email Template Preview

Both emails feature:
- Beautiful gradient headers
- Task title and description
- Scheduled time in IST
- Responsive design
- Professional branding

---

**Need Help?** Check terminal logs for detailed information about what's happening!
