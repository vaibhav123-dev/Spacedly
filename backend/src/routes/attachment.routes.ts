import express from 'express';
import { authMiddleware } from '../middlewares/auth.middleware';
import { upload } from '../middlewares/upload.middleware';
import * as taskController from '../controllers/task.controller';

const router = express.Router();

// All attachment routes require authentication
router.use(authMiddleware);

// Upload attachments to a task
router.post('/:id', upload.array('files', 10), taskController.uploadAttachments);

// Delete attachment
router.delete('/:attachmentId', taskController.deleteAttachment);

export default router;
