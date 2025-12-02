import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import User from '../models/user.model';
import { generateAccessToken } from '../helpers/auth';

export interface CustomRequest extends Request {
  user?: { id: string; email: string };
  body: any;
  params: any;
  files?: any;
  cookies: any;
}

// Helper to send 401
const unauthorized = (res: Response, message = 'Unauthorized Request') =>
  res.status(401).json({ message });

// Helper to verify JWT
const verifyToken = (token: string, secret: string): JwtPayload | null => {
  try {
    return jwt.verify(token, secret) as JwtPayload;
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') return null; // handle expired separately
    throw err; // other errors → invalid token
  }
};

export const authMiddleware = async (
  req: CustomRequest,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { accessToken, refreshToken } = req.cookies;

    if (!accessToken && !refreshToken) return unauthorized(res);

    // 1️⃣ Verify access token
    if (accessToken) {
      try {
        const decodedAccess = verifyToken(
          accessToken,
          process.env.JWT_ACCESS_SECRET!,
        );
        if (decodedAccess) {
          req.user = { id: decodedAccess.id, email: decodedAccess.email };
          return next(); // Access token valid → continue
        }
        // expired → continue to refresh
      } catch {
        // invalid token → try refresh
      }
    }

    // 2️⃣ Verify refresh token
    if (!refreshToken) return unauthorized(res);

    let decodedRefresh;
    try {
      decodedRefresh = jwt.verify(
        refreshToken,
        process.env.JWT_REFRESH_SECRET!,
      ) as JwtPayload;
    } catch {
      return unauthorized(res);
    }

    // 3️⃣ Check user exists + refresh token matches DB
    const user = await User.findByPk(decodedRefresh.id);
    if (!user || user.refresh_token !== refreshToken) return unauthorized(res);

    // 4️⃣ Generate new access token
    const newAccessToken = generateAccessToken(user.id, user.email);

    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000, // 15 min
    });

    req.user = { id: user.id, email: user.email };

    next(); // continue request
  } catch (err) {
    return unauthorized(res);
  }
};
