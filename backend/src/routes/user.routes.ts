import express from 'express';
import {
  enable2FAauth,
  verifyOtp,
  getMe,
} from '../controllers/user.controller';
import { authMiddleware } from '../middlewares/auth.middleware';

const router = express.Router();

// User profile
router.route('/me').get(authMiddleware, getMe);

// 2FA routes
router.route('/verify-otp').post(verifyOtp);
router.route('/enabled-2fa').post(authMiddleware, enable2FAauth);

export default router;
