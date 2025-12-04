import { Response } from 'express';
import { CustomRequest } from '../middlewares/auth.middleware';
import * as notificationService from '../services/notification.service';
import ApiResponse from '../utils/apiResponse';
import asyncWrapper from '../utils/asyncWrapper';

export const getNotifications = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;

  const notifications = await notificationService.getUserNotifications(String(userId));

  return ApiResponse.success(res, { notifications }, 'Notifications retrieved successfully');
});

export const getUnreadCount = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;

  const count = await notificationService.getUnreadCount(String(userId));

  return ApiResponse.success(res, { count }, 'Unread count retrieved successfully');
});

export const markAsRead = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { id: notificationId } = req.params;

  const notification = await notificationService.markAsRead(notificationId, String(userId));

  return ApiResponse.success(res, { notification }, 'Notification marked as read');
});

export const markAllAsRead = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;

  const result = await notificationService.markAllAsRead(String(userId));

  return ApiResponse.success(res, result, 'All notifications marked as read');
});

export const deleteNotification = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const { id: userId } = req.user!;
  const { id: notificationId } = req.params;

  const result = await notificationService.deleteNotification(notificationId, String(userId));

  return ApiResponse.success(res, result, 'Notification deleted successfully');
});
