import express from 'express';
import { authMiddleware } from '../middlewares/auth.middleware';
import { upload } from '../middlewares/upload.middleware';
import * as taskController from '../controllers/task.controller';
import * as reminderController from '../controllers/reminder.controller';

const router = express.Router();

// All task routes require authentication
router.use(authMiddleware);

// Task CRUD
router.post('/', taskController.createTask);
router.get('/', taskController.getTasks);
router.get('/:id', taskController.getTask);
router.put('/:id', taskController.updateTask);
router.delete('/:id', taskController.deleteTask);

// File attachments
router.post('/:id/attachments', upload.array('files', 10), taskController.uploadAttachments);

// Task reminders
router.get('/:taskId/reminders', reminderController.getTaskReminders);

export default router;
