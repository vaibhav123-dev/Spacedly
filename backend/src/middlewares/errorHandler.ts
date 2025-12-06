import { Request, Response, NextFunction } from 'express';
import { ValidationError } from 'joi';
import HTTP_STATUS from '../constants';

const routeNotFound = (req: Request, res: Response, next: NextFunction) => {
  const error = new Error(`Route not found: ${req.originalUrl}`);
  res.status(HTTP_STATUS.NOT_FOUND);
  next(error); // pass the error to the errorHandler
};

const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  // Default to 500 Internal Server Error
  let statusCode = err?.statusCode || HTTP_STATUS.INTERNAL_SERVER_ERROR;
  let message = err?.message || 'Internal Server Error';

  // Handle Joi validation errors
  if (err instanceof ValidationError) {
    statusCode = HTTP_STATUS.BAD_REQUEST;
    // Collect all validation messages
    message = err.details.map((detail) => detail.message).join(', ');
  }

  // Prepare error response
  const errorResponse: any = {
    success: false,
    message,
  };

  // In development, include stack trace for debugging
  if (process.env.NODE_ENV === 'development') {
    errorResponse.stack = err.stack;
    errorResponse.error = err;
  }

  // Log errors in development
  if (process.env.NODE_ENV === 'development') {
    console.error('Error:', {
      statusCode,
      message,
      stack: err.stack,
      path: req.path,
      method: req.method,
    });
  }

  res.status(statusCode).json(errorResponse);
};

export { routeNotFound, errorHandler };
