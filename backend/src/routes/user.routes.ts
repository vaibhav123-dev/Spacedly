import express from 'express';
import {
  enable2FAauth,
  loginUser,
  registerUser,
  verifyOtp,
} from '../controllers/user.controller';
import { authMiddleware } from '../middlewares/auth.middleware';

const router = express.Router();

router.route('/register').post(registerUser);
router.route('/login').post(loginUser);
router.route('/enabled-2fa').post(authMiddleware, enable2FAauth);
router.route('/verify-otp').post(verifyOtp);

export default router;
