import express from 'express';
import userRoutes from './user.routes';
import authRoutes from './auth.routes';
import taskRoutes from './task.routes';
import reminderRoutes from './reminder.routes';
import attachmentRoutes from './attachment.routes';
import notificationRoutes from './notification.routes';
import analyticsRoutes from './analytics.routes';

const router = express.Router();

router.use('/user', userRoutes);
router.use('/auth', authRoutes);
router.use('/tasks', taskRoutes);
router.use('/reminders', reminderRoutes);
router.use('/attachments', attachmentRoutes);
router.use('/notifications', notificationRoutes);
router.use('/analytics', analyticsRoutes);

export default router;
