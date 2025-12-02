import { Request, Response } from 'express';
import { CustomRequest } from '../middlewares/auth.middleware';
import { createTaskSchema, updateTaskSchema } from '../validations/task.validation';
import * as taskService from '../services/task.service';
import ApiResponse from '../utils/apiResponse';
import ApiError from '../utils/apiError';
import HTTP_STATUS from '../constants';
import asyncWrapper from '../utils/asyncWrapper';

export const createTask = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const taskData = req.body;

  await createTaskSchema.validateAsync(taskData);

  const task = await taskService.createTask({ userId: String(userId), ...taskData });

  return ApiResponse.created(res, { task }, 'Task created successfully');
});

export const getTasks = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;

  const tasks = await taskService.getAllUserTasks(String(userId));

  return ApiResponse.success(res, { tasks }, 'Tasks retrieved successfully');
});

export const getTask = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { id: taskId } = req.params;

  const task = await taskService.getTaskById(taskId, String(userId));

  return ApiResponse.success(res, { task }, 'Task retrieved successfully');
});

export const updateTask = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { id: taskId } = req.params;
  const updateData = req.body;

  await updateTaskSchema.validateAsync(updateData);

  const task = await taskService.updateTask(taskId, String(userId), updateData);

  return ApiResponse.success(res, { task }, 'Task updated successfully');
});

export const deleteTask = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { id: taskId } = req.params;

  await taskService.deleteTask(taskId, String(userId));

  return ApiResponse.success(res, {}, 'Task deleted successfully');
});

export const uploadAttachments = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { id: taskId } = req.params;
  const files = req.files as Express.Multer.File[];

  if (!files || files.length === 0) {
    throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'No files uploaded');
  }

  const attachments = await taskService.addTaskAttachments(taskId, String(userId), files);

  return ApiResponse.success(res, { attachments }, 'Files uploaded successfully');
});

export const deleteAttachment = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { attachmentId } = req.params;

  await taskService.deleteAttachment(attachmentId, String(userId));

  return ApiResponse.success(res, {}, 'Attachment deleted successfully');
});
