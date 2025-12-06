import express from 'express';
import path from 'path';
import baseRoutes from './routes/index';
import cookieParser from 'cookie-parser';
import { errorHandler, routeNotFound } from './middlewares/errorHandler';
import passport from './config/passport';
import cors from 'cors';
import './models/associations'; // Initialize model associations
import {
  helmetConfig,
  hppProtection,
  globalLimiter,
  requestTimeout,
  sanitizeInput,
} from './middlewares/security.middleware';

const app = express();

// Trust proxy - important for rate limiting behind reverse proxy
app.set('trust proxy', 1);

// Security headers with Helmet
app.use(helmetConfig);

// Request timeout (30 seconds)
app.use(requestTimeout(30000));

// Enhanced CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : [process.env.FRONTEND_URL || 'http://localhost:8080'];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Set-Cookie'],
    maxAge: 600, // 10 minutes
  })
);

// Body parser with size limits (prevents DoS attacks)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookie parser
app.use(cookieParser());

// HTTP Parameter Pollution protection
app.use(hppProtection);

// Input sanitization (XSS protection + NoSQL injection protection)
app.use(sanitizeInput);

// Global rate limiter
app.use('/api', globalLimiter);

// Serve static files from uploads directory
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Initialize Passport
app.use(passport.initialize());

// routes
app.use('/api', baseRoutes);

// global handlers
app.use(routeNotFound);
app.use(errorHandler);

export default app;
