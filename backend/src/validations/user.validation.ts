import Joi from 'joi';

export const createUserSchema = Joi.object({
  name: Joi.string().min(2).max(50).required().messages({
    'string.base': 'Name must be a valid text.',
    'string.empty': 'Name is required.',
    'string.min': 'Name must be at least 2 characters long.',
    'string.max': 'Name must be less than 50 characters.',
    'any.required': 'Name field is required.',
  }),

  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required()
    .messages({
      'string.base': 'Email must be a valid text.',
      'string.empty': 'Email is required.',
      'string.email': 'Please provide a valid email address.',
      'any.required': 'Email field is required.',
    }),

  password: Joi.string().min(6).max(30).required().messages({
    'string.base': 'Password must be text.',
    'string.empty': 'Password is required.',
    'string.min': 'Password must be at least 6 characters long.',
    'string.max': 'Password cannot exceed 30 characters.',
    'any.required': 'Password field is required.',
  }),
});

export const loginUserSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required()
    .messages({
      'string.base': 'Email must be a valid text.',
      'string.empty': 'Email is required.',
      'string.email': 'Please provide a valid email address.',
      'any.required': 'Email field is required.',
    }),

  password: Joi.string().min(6).max(30).required().messages({
    'string.base': 'Password must be text.',
    'string.empty': 'Password is required.',
    'string.min': 'Password must be at least 6 characters long.',
    'string.max': 'Password cannot exceed 30 characters.',
    'any.required': 'Password field is required.',
  }),
});

export const forgotPasswordSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required()
    .messages({
      'string.base': 'Email must be a valid text.',
      'string.empty': 'Email is required.',
      'string.email': 'Please provide a valid email address.',
      'any.required': 'Email field is required.',
    }),
});

export const resetPasswordSchema = Joi.object({
  token: Joi.string().required().messages({
    'string.base': 'Token must be a valid text.',
    'string.empty': 'Token is required.',
    'any.required': 'Token field is required.',
  }),

  password: Joi.string().min(6).max(30).required().messages({
    'string.base': 'Password must be text.',
    'string.empty': 'Password is required.',
    'string.min': 'Password must be at least 6 characters long.',
    'string.max': 'Password cannot exceed 30 characters.',
    'any.required': 'Password field is required.',
  }),
});

export const toggle2FASchema = Joi.object({
  is_Enabled: Joi.boolean().required().messages({
    'boolean.base': 'is_Enabled must be a boolean value.',
    'any.required': 'is_Enabled field is required.',
  }),
});

export const verifyOtpSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required()
    .messages({
      'string.base': 'Email must be a valid text.',
      'string.empty': 'Email is required.',
      'string.email': 'Please provide a valid email address.',
      'any.required': 'Email field is required.',
    }),

  otp: Joi.string().length(6).pattern(/^[0-9]+$/).required().messages({
    'string.base': 'OTP must be a valid text.',
    'string.empty': 'OTP is required.',
    'string.length': 'OTP must be exactly 6 digits.',
    'string.pattern.base': 'OTP must contain only numbers.',
    'any.required': 'OTP field is required.',
  }),
});

export const setPasswordSchema = Joi.object({
  password: Joi.string().min(6).max(30).required().messages({
    'string.base': 'Password must be text.',
    'string.empty': 'Password is required.',
    'string.min': 'Password must be at least 6 characters long.',
    'string.max': 'Password cannot exceed 30 characters.',
    'any.required': 'Password field is required.',
  }),
});
