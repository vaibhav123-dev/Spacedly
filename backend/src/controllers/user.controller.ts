import {
  createUserSchema,
  loginUserSchema,
} from '../validations/user.validation';
import { Request, Response } from 'express';
import {
  userLogin,
  userRegister,
  initiateTwoFactorAuth,
  verifyTwoFactorOtp,
} from '../services/user.service';
import ApiResponse from '../utils/apiResponse';
import asyncWrapper from '../utils/asyncWrapper';
import { CustomRequest } from '../middlewares/auth.middleware';
import User from '../models/user.model';
import { generateOTP, otpTemplate } from '../helpers/otp';
import HTTP_STATUS from '../constants';
import { sendEmail } from '../utils/emailUtil';
import { generateAccessToken, generateRefreshToken } from '../helpers/auth';
import { setAuthCookies } from '../utils/cookieUtil';

export const registerUser = asyncWrapper(
  async (req: Request, res: Response) => {
    const { name, email, password } = req.body;

    await createUserSchema.validateAsync({ name, email, password });

    const user = await userRegister({ name, email, password });

    return ApiResponse.created(res, { user }, 'User registered successfully');
  },
);

export const loginUser = asyncWrapper(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  await loginUserSchema.validateAsync({ email, password });

  // Check if user has 2FA enabled
  const user = await initiateTwoFactorAuth(email);

  if (user.is_two_factor_enabled) {
    // Generate and send OTP
    const otp = generateOTP();
    user.two_factor_otp = otp;
    user.two_factor_otp_expiry = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();

    // Send OTP email
    await sendEmail(email, 'Your Login OTP', otpTemplate(otp));
    
    return ApiResponse.success(res, {}, 'Otp send to your registered Email ');
  }

  // Regular login without 2FA
  const { accessToken, refreshToken, user_data } = await userLogin({
    email,
    password,
  });

  // Set cookies
  setAuthCookies(res, accessToken, refreshToken);

  return ApiResponse.success(
    res,
    { user: user_data },
    'User logged in Successfully',
  );
});

export const verifyOtp = asyncWrapper(async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return ApiResponse.error(
      res,
      'Email and OTP are required',
      HTTP_STATUS.BAD_REQUEST,
    );
  }

  // Verify OTP and generate tokens
  const { accessToken, refreshToken, user_data } = await verifyTwoFactorOtp(
    email,
    otp,
  );

  // Set cookies
  setAuthCookies(res, accessToken, refreshToken);

  return ApiResponse.success(
    res,
    { user: user_data },
    'OTP verified, user logged in successfully',
  );
});

export const enable2FAauth = asyncWrapper(
  async (req: CustomRequest, res: Response) => {
    const { is_Enabled } = req.body;
    const { id } = req.user;
    const user = await User.findByPk(id);
    
    if (!user) {
      return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
    }
    
    user.is_two_factor_enabled = is_Enabled;
    await user.save();
    return ApiResponse.success(
      res,
      {},
      `2FA auth ${is_Enabled ? 'enabled' : 'disabled'} successfully`,
    );
  },
);

export const googleAuthCallback = asyncWrapper(
  async (req: Request, res: Response) => {
    const user = req.user as User;

    if (!user) {
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=user_not_found`);
    }

    // Generate JWT tokens
    const accessToken = generateAccessToken(user.id, user.email);
    const refreshToken = generateRefreshToken(user.id, user.email);

    // Save refresh token to database
    user.refresh_token = refreshToken;
    await user.save();

    // Set cookies
    setAuthCookies(res, accessToken, refreshToken);

    // Redirect to frontend dashboard
    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  },
);
