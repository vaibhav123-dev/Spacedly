import User from '../models/user.model';
import ApiError from '../utils/apiError';
import {
  comparePassword,
  generateAccessToken,
  generateRefreshToken,
  hashPassword,
} from '../helpers/auth';
import HTTP_STATUS from '../constants';

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
