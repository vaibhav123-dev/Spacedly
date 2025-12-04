import Task from '../models/task.model';
import TaskAttachment from '../models/taskAttachment.model';
import Reminder from '../models/reminder.model';
import ApiError from '../utils/apiError';
import HTTP_STATUS from '../constants';
import fs from 'fs';
import path from 'path';
import { cacheService } from './cache.service';

interface CreateTaskInput {
  userId: string;
  title: string;
  description?: string;
  category: 'Study' | 'Work' | 'Personal';
  priority: 'Low' | 'Medium' | 'High';
  link?: string;
}

interface UpdateTaskInput {
  title?: string;
  description?: string;
  category?: 'Study' | 'Work' | 'Personal';
  priority?: 'Low' | 'Medium' | 'High';
  link?: string;
}

export const createTask = async (taskData: CreateTaskInput) => {
  const task = await Task.create(taskData as any);
  
  // Clear analytics cache
  await cacheService.del(`analytics:${taskData.userId}`);
  
  return task;
};

export const getAllUserTasks = async (userId: string) => {
  const tasks = await Task.findAll({
    where: { userId },
    include: [
      {
        model: TaskAttachment,
        as: 'attachments',
        attributes: ['id', 'fileName', 'originalName', 'fileSize', 'fileType', 'fileUrl'],
      },
    ],
    order: [['createdAt', 'DESC']],
  });

  return tasks;
};

export const getTaskById = async (taskId: string, userId: string) => {
  const task = await Task.findOne({
    where: { id: taskId, userId },
    include: [
      {
        model: TaskAttachment,
        as: 'attachments',
        attributes: ['id', 'fileName', 'originalName', 'fileSize', 'fileType', 'fileUrl'],
      },
    ],
  });

  if (!task) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Task not found');
  }

  return task;
};

export const updateTask = async (
  taskId: string,
  userId: string,
  updateData: UpdateTaskInput
) => {
  const task = await Task.findOne({ where: { id: taskId, userId } });

  if (!task) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Task not found');
  }

  await task.update(updateData);
  
  // Clear analytics cache
  await cacheService.del(`analytics:${userId}`);
  
  // Fetch updated task with attachments
  const updatedTask = await getTaskById(taskId, userId);
  return updatedTask;
};

export const deleteTask = async (taskId: string, userId: string) => {
  const task = await Task.findOne({
    where: { id: taskId, userId },
    include: [{ model: TaskAttachment, as: 'attachments' }],
  });

  if (!task) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Task not found');
  }

  // Delete all attachment files from disk
  const attachments = await TaskAttachment.findAll({ where: { taskId } });
  for (const attachment of attachments) {
    const filePath = path.join(__dirname, '../../uploads', attachment.fileName);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  // Delete task (cascade will delete attachments and reminders from DB)
  await task.destroy();
  
  // Clear analytics cache
  await cacheService.del(`analytics:${userId}`);
};

export const addTaskAttachments = async (
  taskId: string,
  userId: string,
  files: Express.Multer.File[]
) => {
  // Verify task belongs to user
  const task = await Task.findOne({ where: { id: taskId, userId } });
  if (!task) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Task not found');
  }

  const attachments = [];
  for (const file of files) {
    const attachment = await TaskAttachment.create({
      taskId,
      fileName: file.filename,
      originalName: file.originalname,
      fileSize: file.size,
      fileType: file.mimetype,
      fileUrl: `/uploads/${file.filename}`,
    });
    attachments.push(attachment);
  }

  return attachments;
};

export const deleteAttachment = async (
  attachmentId: string,
  userId: string
) => {
  const attachment = await TaskAttachment.findOne({
    where: { id: attachmentId },
    include: [{ model: Task, as: 'task', where: { userId } }],
  });

  if (!attachment) {
    throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Attachment not found');
  }

  // Delete file from disk
  const filePath = path.join(__dirname, '../../uploads', attachment.fileName);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  await attachment.destroy();
};
