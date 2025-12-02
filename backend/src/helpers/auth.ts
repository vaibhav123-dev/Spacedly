import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

// Function to hash the password
export const hashPassword = async (password: string): Promise<string> => {
  return await bcrypt.hash(password, 10);
};

// Function to compare password
export const comparePassword = async (
  password: string,
  hashedPassword: string,
): Promise<boolean> => {
  return await bcrypt.compare(password, hashedPassword);
};

// Function to generate JWT token

export const generateAccessToken = (userId: string, email: string): string => {
  const payload = { id: userId, email };

  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: '15m',
  });
};

export const generateRefreshToken = (userId: string, email: string): string => {
  const payload = { id: userId, email };

  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: '30d',
  });
};

// Function to set authentication cookies
export const setAuthCookies = (
  res: any,
  accessToken: string,
  refreshToken: string,
): void => {
  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 15 * 60 * 1000, // 15 mins
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  });
};
