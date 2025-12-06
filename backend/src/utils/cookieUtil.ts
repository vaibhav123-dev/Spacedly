import { Response } from 'express';

/**
 * Set authentication cookies (access and refresh tokens) with enhanced security
 */
export const setAuthCookies = (
  res: Response,
  accessToken: string,
  refreshToken: string,
): void => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Common cookie options for enhanced security
  const cookieOptions = {
    httpOnly: true, // Prevents JavaScript access
    secure: isProduction, // HTTPS only in production
    sameSite: (isProduction ? 'strict' : 'lax') as 'strict' | 'lax', // CSRF protection
    path: '/', // Available across entire domain
    domain: isProduction ? process.env.COOKIE_DOMAIN : undefined, // Specify domain in production
  };

  res.cookie('accessToken', accessToken, {
    ...cookieOptions,
    maxAge: 15 * 60 * 1000, // 15 minutes
  });

  res.cookie('refreshToken', refreshToken, {
    ...cookieOptions,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

/**
 * Clear authentication cookies
 */
export const clearAuthCookies = (res: Response): void => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  const cookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: (isProduction ? 'strict' : 'lax') as 'strict' | 'lax',
    path: '/',
    domain: isProduction ? process.env.COOKIE_DOMAIN : undefined,
  };

  res.clearCookie('accessToken', cookieOptions);
  res.clearCookie('refreshToken', cookieOptions);
};
