import { Response } from 'express';

/**
 * Set authentication cookies (access and refresh tokens)
 */
export const setAuthCookies = (
  res: Response,
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
