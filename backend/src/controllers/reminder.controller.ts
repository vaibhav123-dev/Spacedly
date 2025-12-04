import { Response } from 'express';
import { CustomRequest } from '../middlewares/auth.middleware';
import { createReminderSchema, updateReminderSchema } from '../validations/reminder.validation';
import * as reminderService from '../services/reminder.service';
import { triggerMorningReminders, triggerHourBeforeReminders } from '../services/reminderCron.service';
import ApiResponse from '../utils/apiResponse';
import asyncWrapper from '../utils/asyncWrapper';

export const createReminder = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const reminderData = req.body;

  await createReminderSchema.validateAsync(reminderData);

  const reminder = await reminderService.createReminder({
    userId: String(userId),
    ...reminderData,
  });

  return ApiResponse.created(res, { reminder }, 'Reminder created successfully');
});

export const getReminders = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;

  const reminders = await reminderService.getAllUserReminders(String(userId));

  return ApiResponse.success(res, { reminders }, 'Reminders retrieved successfully');
});

export const getTaskReminders = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { taskId } = req.params;

  const reminders = await reminderService.getTaskReminders(taskId, String(userId));

  return ApiResponse.success(res, { reminders }, 'Task reminders retrieved successfully');
});

export const updateReminder = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { id: reminderId } = req.params;
  const updateData = req.body;

  await updateReminderSchema.validateAsync(updateData);

  const reminder = await reminderService.updateReminder(reminderId, String(userId), updateData);

  return ApiResponse.success(res, { reminder }, 'Reminder updated successfully');
});

export const deleteReminder = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { id: reminderId } = req.params;

  await reminderService.deleteReminder(reminderId, String(userId));

  return ApiResponse.success(res, {}, 'Reminder deleted successfully');
});

// Test endpoints for manual email triggering
export const testMorningReminders = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const count = await triggerMorningReminders();
  
  return ApiResponse.success(res, { emailsSent: count }, `Morning reminder emails sent: ${count}`);
});

export const testHourBeforeReminders = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const count = await triggerHourBeforeReminders();
  
  return ApiResponse.success(res, { emailsSent: count }, `1-hour-before reminder emails sent: ${count}`);
});
