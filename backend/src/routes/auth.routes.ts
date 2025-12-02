import express from 'express';
import passport from '../config/passport';
import { googleAuthCallback } from '../controllers/user.controller';

const router = express.Router();

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
