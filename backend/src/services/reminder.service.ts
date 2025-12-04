import Reminder from '../models/reminder.model';
import Task from '../models/task.model';
import ApiError from '../utils/apiError';
import HTTP_STATUS from '../constants';
import { cacheService } from './cache.service';

interface CreateReminderInput {
  taskId: string;
  userId: string;
  scheduledAt: Date;
  status?: 'pending' | 'completed' | 'skipped';
}

interface UpdateReminderInput {
  scheduledAt?: Date;
  status?: 'pending' | 'completed' | 'skipped';
}

export const createReminder = async (reminderData: CreateReminderInput) => {
  // Verify task belongs to user
  const task = await Task.findOne({
    where: { id: reminderData.taskId, userId: reminderData.userId },
  });

  if (!task) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Task not found');
  }

  const reminder = await Reminder.create(reminderData as any);
  
  // Clear analytics cache
  await cacheService.del(`analytics:${reminderData.userId}`);
  
  return reminder;
};

export const getAllUserReminders = async (userId: string) => {
  const reminders = await Reminder.findAll({
    where: { userId },
    include: [{ model: Task, as: 'task' }],
    order: [['scheduledAt', 'ASC']],
  });

  return reminders;
};

export const getTaskReminders = async (taskId: string, userId: string) => {
  // Verify task belongs to user
  const task = await Task.findOne({ where: { id: taskId, userId } });
  if (!task) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Task not found');
  }

  const reminders = await Reminder.findAll({
    where: { taskId },
    order: [['scheduledAt', 'ASC']],
  });

  return reminders;
};

export const updateReminder = async (
  reminderId: string,
  userId: string,
  updateData: UpdateReminderInput
) => {
  const reminder = await Reminder.findOne({
    where: { id: reminderId, userId },
  });

  if (!reminder) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Reminder not found');
  }

  await reminder.update(updateData);
  
  // Clear analytics cache
  await cacheService.del(`analytics:${userId}`);
  
  return reminder;
};

export const deleteReminder = async (reminderId: string, userId: string) => {
  const reminder = await Reminder.findOne({
    where: { id: reminderId, userId },
  });

  if (!reminder) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Reminder not found');
  }

  await reminder.destroy();
  
  // Clear analytics cache
  await cacheService.del(`analytics:${userId}`);
};
