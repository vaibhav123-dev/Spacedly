import { Request, Response, NextFunction } from 'express';
import { ValidationError } from 'joi';

const routeNotFound = (req: Request, res: Response, next: NextFunction) => {
  const error = new Error(`Route not found: ${req.originalUrl}`);
  res.status(404); // this is fine here
  next(error); // pass the error to the errorHandler
};

const errorHandler = (err, req: Request, res: Response, next: NextFunction) => {
  // If statusCode not set, default to 500
  let statusCode = err?.statusCode || 500;
  let message = err?.message;

  if (err.statusCode) {
    statusCode = err.statusCode;
    message = err.message;
  }
  // 2. Handle Joi validation errors
  else if (err instanceof ValidationError) {
    statusCode = 400;
    // Collect all validation messages
    message = err.details.map((detail) => detail.message).join(', ');
  }

  res.status(statusCode).json({
    success: false,
    message,
  });
};

export { routeNotFound, errorHandler };
