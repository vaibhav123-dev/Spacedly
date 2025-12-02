import Joi from 'joi';

export const createTaskSchema = Joi.object({
  title: Joi.string().required().min(1).max(255).messages({
    'string.empty': 'Title is required',
    'string.min': 'Title must be at least 1 character long',
    'string.max': 'Title cannot exceed 255 characters',
  }),
  description: Joi.string().allow('').optional(),
  category: Joi.string().valid('Study', 'Work', 'Personal').required().messages({
    'any.only': 'Category must be one of: Study, Work, Personal',
  }),
  priority: Joi.string().valid('Low', 'Medium', 'High').required().messages({
    'any.only': 'Priority must be one of: Low, Medium, High',
  }),
  link: Joi.string().uri().allow('').optional().messages({
    'string.uri': 'Link must be a valid URL',
  }),
});

export const updateTaskSchema = Joi.object({
  title: Joi.string().min(1).max(255).optional(),
  description: Joi.string().allow('').optional(),
  category: Joi.string().valid('Study', 'Work', 'Personal').optional(),
  priority: Joi.string().valid('Low', 'Medium', 'High').optional(),
  link: Joi.string().uri().allow('').optional(),
});
