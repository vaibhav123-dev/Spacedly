import User from '../models/user.model';
import ApiError from '../utils/apiError';
import {
  comparePassword,
  generateAccessToken,
  generateRefreshToken,
  hashPassword,
} from '../helpers/auth';
import HTTP_STATUS from '../constants';
import crypto from 'crypto';

export const userRegister = async ({ name, email, password }) => {
  const existingUser = await User.findOne({ where: { email } });

  if (existingUser) {
    throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User already exists');
  }

  const hashpassword = await hashPassword(password);

  const user = await User.create({ name, email, password: hashpassword });

  return {
    id: user.id,
    name: user.name,
    email: user.email,
  };
};

export const userLogin = async ({ email, password }) => {
  const user = await User.findOne({ where: { email } });

  if (!user || !(await comparePassword(password, user?.password))) {
    throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid credentials');
  }

  const accessToken = generateAccessToken(user.id, user.email);
  const refreshToken = generateRefreshToken(user.id, user.email);

  user.refresh_token = refreshToken;
  await user.save();

  return {
    refreshToken,
    accessToken,
    user_data: {
      id: user.id,
      name: user.name,
      email: user.email,
      is_two_factor_enabled: user.is_two_factor_enabled,
    },
  };
};

export const initiateTwoFactorAuth = async (email: string) => {
  const user = await User.findOne({ where: { email } });

  if (!user) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'User not found');
  }

  return user;
};

export const verifyTwoFactorOtp = async (email: string, otp: string) => {
  const user = await User.findOne({ where: { email } });

  if (!user) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'User not found');
  }

  // Check OTP
  if (user.two_factor_otp !== otp) {
    throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid OTP');
  }

  // Check expiry
  if (new Date() > new Date(user.two_factor_otp_expiry)) {
    throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'OTP expired');
  }

  // OTP is valid → clear it
  user.two_factor_otp = null;
  user.two_factor_otp_expiry = null;

  // Generate tokens
  const accessToken = generateAccessToken(user.id, user.email);
  const refreshToken = generateRefreshToken(user.id, user.email);

  user.refresh_token = refreshToken;
  await user.save();

  return {
    accessToken,
    refreshToken,
    user_data: {
      id: user.id,
      name: user.name,
      email: user.email,
      is_two_factor_enabled: user.is_two_factor_enabled,
    },
  };
};

export const forgotPasswordService = async (email: string) => {
  const user = await User.findOne({ where: { email } });

  // Don't reveal if user exists for security reasons
  if (!user) {
    return {
      message: 'If the email exists, a password reset link has been sent',
    };
  }

  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString('hex');

  // Hash token before saving (optional but recommended)
  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // Set token and expiration (1 hour)
  user.reset_password_token = hashedToken;
  user.reset_password_expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  await user.save();

  return {
    resetToken, // Return unhashed token to send in email
    user,
  };
};

export const resetPasswordService = async (
  token: string,
  newPassword: string,
) => {
  // Hash the provided token to match with database
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const user = await User.findOne({
    where: { reset_password_token: hashedToken },
  });

  if (!user) {
    throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid or expired reset token');
  }

  // Check if token has expired
  if (new Date() > new Date(user.reset_password_expires!)) {
    throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Reset token has expired');
  }

  // Hash new password
  const hashedPassword = await hashPassword(newPassword);

  // Update password and clear reset token fields
  user.password = hashedPassword;
  user.reset_password_token = null;
  user.reset_password_expires = null;
  user.refresh_token = null; // Logout all sessions
  await user.save();

  return {
    message: 'Password has been reset successfully',
  };
};
