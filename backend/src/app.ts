import express from 'express';
import path from 'path';
import baseRoutes from './routes/index';
import cookieParser from 'cookie-parser';
import { errorHandler, routeNotFound } from './middlewares/errorHandler';
import passport from './config/passport';
import cors from 'cors';
import './models/associations'; // Initialize model associations

const app = express();

// CORS configuration for OAuth
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

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
