import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import hpp from 'hpp';
import HTTP_STATUS from '../constants';

// Helmet configuration for security headers
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
});

// HTTP Parameter Pollution protection
export const hppProtection = hpp({
  whitelist: [
    'sort',
    'fields',
    'page',
    'limit',
    'status',
    'priority',
    'category',
  ],
});

// Global API rate limiter - 100 requests per 15 minutes per IP
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      message: 'Too many requests from this IP, please try again after 15 minutes.',
    });
  },
});

// Strict rate limiter for authentication routes - 5 attempts per 15 minutes
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  skipSuccessfulRequests: true,
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      message: 'Too many login attempts from this IP. Please try again after 15 minutes.',
    });
  },
});

// Password reset rate limiter - 3 attempts per hour
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  skipSuccessfulRequests: true,
  message: 'Too many password reset attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      message: 'Too many password reset requests. Please try again after 1 hour.',
    });
  },
});

// File upload rate limiter - 10 uploads per hour
export const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Too many file uploads, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      message: 'Upload limit exceeded. Please try again after 1 hour.',
    });
  },
});

// OTP verification rate limiter - 5 attempts per 15 minutes
export const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  skipSuccessfulRequests: true,
  message: 'Too many OTP verification attempts.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      message: 'Too many OTP verification attempts. Please try again after 15 minutes.',
    });
  },
});

// Request timeout middleware
export const requestTimeout = (timeout: number = 30000) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const timer = setTimeout(() => {
      res.status(HTTP_STATUS.REQUEST_TIMEOUT).json({
        success: false,
        message: 'Request timeout',
      });
    }, timeout);

    res.on('finish', () => clearTimeout(timer));
    res.on('close', () => clearTimeout(timer));

    next();
  };
};

// Input sanitization middleware (XSS + NoSQL injection protection)
export const sanitizeInput = (req: Request, res: Response, next: NextFunction) => {
  // Sanitize body
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  
  // For params, create sanitized version (params is read-only in Express 5)
  if (req.params) {
    const sanitizedParams = sanitizeObject(req.params);
    // Override getter to return sanitized params
    Object.defineProperty(req, 'params', {
      value: sanitizedParams,
      writable: true,
      configurable: true,
    });
  }
  
  // For query, create sanitized version (query is read-only in Express 5)
  if (req.query) {
    const sanitizedQuery = sanitizeObject(req.query);
    // Override getter to return sanitized query
    Object.defineProperty(req, 'query', {
      value: sanitizedQuery,
      writable: true,
      configurable: true,
    });
  }
  
  next();
};

// Helper function to sanitize objects
function sanitizeObject(obj: any): any {
  if (typeof obj !== 'object' || obj === null) {
    return sanitizeValue(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }

  const sanitized: any = {};
  for (const key in obj) {
    // Use Object.prototype.hasOwnProperty.call for compatibility
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      sanitized[key] = sanitizeObject(obj[key]);
    }
  }
  return sanitized;
}

// Helper function to sanitize individual values
function sanitizeValue(value: any): any {
  if (typeof value === 'string') {
    // NoSQL injection protection - remove MongoDB operators
    if (value.startsWith('$') || value.includes('$where')) {
      console.warn(`Blocked potential NoSQL injection attempt: ${value.substring(0, 50)}`);
      return value.replace(/\$/g, '').replace(/\$where/gi, '');
    }
    
    // XSS protection - remove potentially dangerous characters but preserve normal text
    return value
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .trim();
  }
  
  // Prevent object-based NoSQL injection
  if (typeof value === 'object' && value !== null) {
    // Check for MongoDB operators in object keys
    const keys = Object.keys(value);
    const hasDangerousKeys = keys.some(key => key.startsWith('$'));
    if (hasDangerousKeys) {
      console.warn('Blocked object with MongoDB operators');
      // Remove keys that start with $
      const sanitized: any = {};
      keys.forEach(key => {
        if (!key.startsWith('$')) {
          sanitized[key] = value[key];
        }
      });
      return sanitized;
    }
  }
  
  return value;
}
