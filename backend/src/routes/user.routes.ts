import express from 'express';
import {
  enable2FAauth,
  getMe,
  setPassword,
} from '../controllers/user.controller';
import { authMiddleware } from '../middlewares/auth.middleware';

const router = express.Router();

// User profile
router.route('/me').get(authMiddleware, getMe);

// 2FA routes
// Note: verify-otp is in auth.routes.ts with proper rate limiting
router.route('/enabled-2fa').post(authMiddleware, enable2FAauth);

// Set password for OAuth users
router.route('/set-password').post(authMiddleware, setPassword);

export default router;
