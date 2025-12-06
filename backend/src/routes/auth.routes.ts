import express from 'express';
import passport from '../config/passport';
import {
  googleAuthCallback,
  forgotPassword,
  resetPassword,
  loginUser,
  registerUser,
  logout,
  verifyOtp,
} from '../controllers/user.controller';
import { authMiddleware } from '../middlewares/auth.middleware';
import {
  authLimiter,
  passwordResetLimiter,
  otpLimiter,
} from '../middlewares/security.middleware';

const router = express.Router();

// Auth routes with rate limiting
router.post('/register', authLimiter, registerUser);
router.post('/login', authLimiter, loginUser);
router.post('/verify-otp', otpLimiter, verifyOtp);
router.post('/logout', authMiddleware, logout);

// Password reset routes with rate limiting
router.post('/forgot-password', passwordResetLimiter, forgotPassword);
router.post('/reset-password', passwordResetLimiter, resetPassword);

// Initiate Google OAuth flow
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
  })
);

// Google OAuth callback
router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=google_auth_failed`,
    session: false,
  }),
  googleAuthCallback
);

export default router;
