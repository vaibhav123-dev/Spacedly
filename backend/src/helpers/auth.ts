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

export const generateAccessToken = (userId: number, email: string): string => {
  const payload = { id: userId, email };

  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: '15m',
  });
};

export const generateRefreshToken = (userId: number, email: string): string => {
  const payload = { id: userId, email };

  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: '30d',
  });
};
