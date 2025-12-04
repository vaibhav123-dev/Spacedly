import express from 'express';
import { authMiddleware } from '../middlewares/auth.middleware';
import * as reminderController from '../controllers/reminder.controller';

const router = express.Router();

// All reminder routes require authentication
router.use(authMiddleware);

// Reminder CRUD
router.post('/', reminderController.createReminder);
router.get('/', reminderController.getReminders);
router.put('/:id', reminderController.updateReminder);
router.delete('/:id', reminderController.deleteReminder);

// Test endpoints for manual email triggering
router.post('/test/morning-reminders', reminderController.testMorningReminders);
router.post('/test/hour-before-reminders', reminderController.testHourBeforeReminders);

export default router;
