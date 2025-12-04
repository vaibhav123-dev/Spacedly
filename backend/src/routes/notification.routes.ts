import express from 'express';
import { authMiddleware } from '../middlewares/auth.middleware';
import * as notificationController from '../controllers/notification.controller';

const router = express.Router();

// All notification routes require authentication
router.use(authMiddleware);

// Get all notifications
router.get('/', notificationController.getNotifications);

// Get unread count
router.get('/count', notificationController.getUnreadCount);

// Mark single notification as read
router.patch('/:id/read', notificationController.markAsRead);

// Mark all notifications as read
router.patch('/read-all', notificationController.markAllAsRead);

// Delete notification
router.delete('/:id', notificationController.deleteNotification);

export default router;
