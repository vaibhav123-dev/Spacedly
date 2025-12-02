import express from 'express';
import { authMiddleware } from '../middlewares/auth.middleware';
import * as taskController from '../controllers/task.controller';

const router = express.Router();

// All attachment routes require authentication
router.use(authMiddleware);

// Delete attachment
router.delete('/:attachmentId', taskController.deleteAttachment);

export default router;
