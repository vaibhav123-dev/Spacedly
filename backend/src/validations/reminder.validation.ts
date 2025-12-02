import Joi from 'joi';

export const createReminderSchema = Joi.object({
  taskId: Joi.string().uuid().required().messages({
    'string.empty': 'Task ID is required',
    'string.uuid': 'Task ID must be a valid UUID',
  }),
  scheduledAt: Joi.date().iso().required().messages({
    'date.base': 'Scheduled date must be a valid date',
    'date.format': 'Scheduled date must be in ISO format',
  }),
  status: Joi.string().valid('pending', 'completed', 'skipped').optional(),
});

export const updateReminderSchema = Joi.object({
  scheduledAt: Joi.date().iso().optional(),
  status: Joi.string().valid('pending', 'completed', 'skipped').optional(),
});
