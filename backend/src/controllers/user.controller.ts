import {
  createUserSchema,
  loginUserSchema,
} from '../validations/user.validation';
import { Request, Response } from 'express';
import { userLogin, userRegister } from '../services/user.service';
import ApiResponse from '../utils/apiResponse';
import asyncWrapper from '../utils/asyncWrapper';
import { CustomRequest } from '../middlewares/auth.middleware';
import User from '../models/user.model';
import { generateOTP, otpTemplate } from '../helpers/otp';
import HTTP_STATUS from '../constants';
import { sendEmail } from '../utils/emailUtil';
import { generateAccessToken, generateRefreshToken } from '../helpers/auth';

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

  const user = await User.findOne({ where: { email } });

  if (user && user.is_two_factor_enabled) {
    const otp = generateOTP();
    user.two_factor_otp = otp;
    user.two_factor_otp_expiry = new Date(Date.now() + 5 * 60 * 1000);
    console.log(user, 'user');
    await user.save();
    console.log(user, otp, 'newuser');
    // Send OTP email
    await sendEmail(email, 'Your Login OTP', otpTemplate(otp));
    return ApiResponse.success(res, {}, 'Otp send to your registered Email ');
  } else {
    const { accessToken, refreshToken, user_data } = await userLogin({
      email,
      password,
    });

    // Send cookies
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 mins
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1d days
    });

    return ApiResponse.success(
      res,
      { user: user_data },
      'User logged in Successfully',
    );
  }
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
  console.log(email, otp, 'console');
  const user = await User.findOne({ where: { email } });
  console.log(user, 'verifuser');
  if (!user) {
    return ApiResponse.error(res, 'User not found', HTTP_STATUS.NOT_FOUND);
  }

  // Check OTP
  if (user.two_factor_otp !== otp) {
    return ApiResponse.error(res, 'Invalid OTP', HTTP_STATUS.BAD_REQUEST);
  }

  // Check expiry
  // if (new Date() > new Date(user.two_factor_otp_expiry)) {
  //   return ApiResponse.error(res, 'OTP expired', HTTP_STATUS.BAD_REQUEST);
  // }

  // OTP is valid → clear it
  user.two_factor_otp = null;
  user.two_factor_otp_expiry = null;
  await user.save();

  // Generate tokens
  const accessToken = generateAccessToken(user.id, user.email);
  const refreshToken = generateRefreshToken(user.id, user.email);

  // Send cookie
  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000,
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000,
  });

  const userData = {
    id: user.id,
    name: user.name,
    email: user.email,
    is_two_factor_enabled: user.is_two_factor_enabled,
  };
  return ApiResponse.success(
    res,
    { user: userData },
    'OTP verified, user logged in successfully',
  );
});

export const enable2FAauth = asyncWrapper(
  async (req: CustomRequest, res: Response) => {
    const { is_Enabled } = req.body;
    const { id } = req.user;
    const user = await User.findByPk(id);
    user.is_two_factor_enabled = is_Enabled;
    await user.save();
    return ApiResponse.success(
      res,
      {},
      `2FA auth ${is_Enabled ? 'enabled' : 'disabled'} successfully`,
    );
  },
);
