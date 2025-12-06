import express from 'express';
import { authMiddleware } from '../middlewares/auth.middleware';
import { upload, optimizeAndUpload } from '../middlewares/upload.middleware';
import { uploadLimiter } from '../middlewares/security.middleware';
import * as taskController from '../controllers/task.controller';

const router = express.Router();

// All attachment routes require authentication
router.use(authMiddleware);

// Upload attachments to a task with rate limiting and optimization
// Supports multiple files (up to 10)
router.post('/:id', uploadLimiter, upload.array('files', 10), optimizeAndUpload, taskController.uploadAttachments);

// Delete attachment
router.delete('/:attachmentId', taskController.deleteAttachment);

export default router;
