import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import User from '../models/user.model';
import dotenv from 'dotenv';

dotenv.config();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || '/api/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Extract email from Google profile
        const email = profile.emails?.[0]?.value;
        
        if (!email) {
          return done(new Error('No email found from Google'), null);
        }

        // Check if user already exists with this Google ID
        let user = await User.findOne({ where: { google_id: profile.id } });

        if (!user) {
          // Check if user exists with this email (local account)
          user = await User.findOne({ where: { email } });

          if (user) {
            // Link Google account to existing local account
            user.google_id = profile.id;
            user.auth_provider = 'google';
            user.name = profile.displayName || user.name;
            await user.save();
          } else {
            // Create new user with Google account
            user = await User.create({
              name: profile.displayName || 'Google User',
              email,
              google_id: profile.id,
              auth_provider: 'google',
              password: null, // No password for Google users
              is_two_factor_enabled: false,
            });
          }
        }

        return done(null, user);
      } catch (error) {
        return done(error as Error, null);
      }
    }
  )
);

export default passport;
