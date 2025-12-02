import express from 'express';
import userRoutes from './user.routes';
import authRoutes from './auth.routes';
import taskRoutes from './task.routes';
import reminderRoutes from './reminder.routes';
import attachmentRoutes from './attachment.routes';

const router = express.Router();

router.use('/user', userRoutes);
router.use('/auth', authRoutes);
router.use('/tasks', taskRoutes);
router.use('/reminders', reminderRoutes);
router.use('/attachments', attachmentRoutes);

export default router;
