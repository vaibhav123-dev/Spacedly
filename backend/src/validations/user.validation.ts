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
