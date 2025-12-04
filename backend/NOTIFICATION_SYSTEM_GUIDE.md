# Notification System - Complete Guide

## 🎉 System Overview

The notification system automatically creates in-app notifications when reminder emails are sent, and displays them with a badge count on the sidebar.

---

## ✅ What Was Implemented

### **1. Database**
- ✅ Created `notifications` table with migration
- ✅ Fields: `id`, `userId`, `type`, `title`, `message`, `isRead`, `relatedTaskId`
- ✅ Types: `overdue`, `upcoming`, `reminder`, `general`
- ✅ Indexes added for performance

### **2. Backend Structure**
```
backend/src/
├── models/notification.model.ts          ✅ Created
├── controllers/notification.controller.ts ✅ Created
├── services/notification.service.ts       ✅ Created
├── routes/notification.routes.ts          ✅ Created
└── migrations/20251204050403-create-notifications-table.js ✅ Created
```

### **3. API Endpoints**
All routes require authentication (`/api/notifications`):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Get all user notifications |
| GET | `/count` | Get unread notification count |
| PATCH | `/:id/read` | Mark single notification as read |
| PATCH | `/read-all` | Mark all notifications as read |
| DELETE | `/:id` | Delete a notification |

### **4. Auto-Generated Notifications**
Notifications are automatically created when:
- ✅ **Morning email sent** (5 AM IST)
  - Type: `reminder`
  - Title: "🌅 Good Morning Reminder"
  - Message: Task details with scheduled time
  
- ✅ **1-hour-before email sent**
  - Type: `upcoming`
  - Title: "⏰ Task Starting Soon"
  - Message: Task starts in 1 hour

### **5. Frontend Integration**
- ✅ Notification badge on sidebar Bell icon
- ✅ Shows unread count (max display: 9+)
- ✅ Real-time updates when notifications change
- ✅ Notifications page displays all notifications
- ✅ Mark as read functionality

---

## 🧪 Testing the System

### **Method 1: Test with Manual Endpoints**

1. **Start the backend**:
   ```bash
   cd Spacedly/backend
   npm run dev
   ```

2. **Create a task with reminder** (via UI or API)

3. **Trigger email manually**:
   ```bash
   # Login first to get token
   POST http://localhost:5000/api/auth/login
   {
     "email": "your@email.com",
     "password": "yourpassword"
   }
   
   # Then trigger reminders
   POST http://localhost:5000/api/reminders/test/hour-before-reminders
   Authorization: Bearer YOUR_TOKEN
   ```

4. **Check for notifications**:
   - Go to Notifications page in UI
   - You should see a notification created
   - Bell icon should show badge count

### **Method 2: Real Cron Test**

1. Create a task with reminder for 1 hour from now
2. Keep backend running (`npm run dev`)
3. Wait for cron to run (every hour at :00)
4. Both email AND notification will be created automatically
5. Check:
   - Email inbox ✉️
   - Notifications page in app 🔔
   - Badge count on sidebar 🔴

---

## 📊 Notification Flow

```
User Creates Task with Reminder
         ↓
Cron Job Runs (Hourly)
         ↓
Email Service Triggered
         ↓
    ┌─────────┴─────────┐
    ↓                   ↓
Send Email         Create Notification
    ↓                   ↓
Gmail ✉️          Database 💾
                        ↓
                   Frontend Fetches
                        ↓
                   Shows Badge 🔴
                        ↓
                   User Clicks Bell
                        ↓
                  Notifications Page
```

---

## 🎯 API Response Examples

### Get Notifications
```json
GET /api/notifications

Response:
{
  "success": true,
  "message": "Notifications retrieved successfully",
  "data": {
    "notifications": [
      {
        "id": "uuid",
        "userId": "uuid",
        "type": "upcoming",
        "title": "⏰ Task Starting Soon",
        "message": "Your task \"Complete Report\" starts in 1 hour at...",
        "isRead": false,
        "relatedTaskId": "uuid",
        "task": {
          "id": "uuid",
          "title": "Complete Report"
        },
        "createdAt": "2025-12-04T10:00:00.000Z"
      }
    ]
  }
}
```

### Get Unread Count
```json
GET /api/notifications/count

Response:
{
  "success": true,
  "message": "Unread count retrieved successfully",
  "data": {
    "count": 3
  }
}
```

### Mark as Read
```json
PATCH /api/notifications/:id/read

Response:
{
  "success": true,
  "message": "Notification marked as read",
  "data": {
    "notification": {
      "id": "uuid",
      "isRead": true,
      ...
    }
  }
}
```

---

## 🔔 Notification Badge

The sidebar Bell icon now shows:
- **No badge**: 0 unread notifications
- **Number (1-9)**: Exact count
- **9+**: More than 9 unread

Badge updates automatically when:
- New notification created
- Notification marked as read
- Notification deleted

---

## 🐛 Troubleshooting

### No Notifications Appearing?

1. **Check backend is running**:
   ```bash
   cd Spacedly/backend
   npm run dev
   ```

2. **Check database migration ran**:
   ```bash
   npx sequelize-cli db:migrate:status
   ```
   Should show `20251204050403-create-notifications-table` as **up**

3. **Check terminal logs** when email is sent:
   ```
   [Morning Email] Sent to user@example.com for task: Task Title
   ```
   Should be followed by notification creation

4. **Check notifications in database**:
   ```sql
   SELECT * FROM notifications ORDER BY createdAt DESC LIMIT 5;
   ```

### Badge Not Showing?

1. **Check unread count endpoint**:
   ```bash
   GET http://localhost:5000/api/notifications/count
   Authorization: Bearer YOUR_TOKEN
   ```

2. **Refresh the page** - badge updates on component mount

3. **Check browser console** for any API errors

---

## 📝 Future Enhancements

Possible additions:
- [ ] Mark all as read button in notification page
- [ ] Delete all read notifications
- [ ] Notification preferences (enable/disable types)
- [ ] Push notifications (browser API)
- [ ] Email notification settings
- [ ] Notification grouping by type

---

## ✅ Success Checklist

- [x] Database table created
- [x] Backend routes working
- [x] Notifications auto-created with emails
- [x] Sidebar badge shows count
- [x] Notifications page displays correctly
- [x] Mark as read functionality works
- [x] Real-time updates working
- [x] TypeScript compilation successful

---

## 🚀 Production Deployment

When deploying:
1. Run migration: `npx sequelize-cli db:migrate`
2. Ensure environment variables are set
3. Backend stays running 24/7
4. Notifications created automatically with cron
5. No manual intervention needed

---

**System is complete and ready to use!** 🎊
