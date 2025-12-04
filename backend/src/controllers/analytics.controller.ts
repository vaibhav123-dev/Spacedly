import { Response } from 'express';
import { CustomRequest } from '../middlewares/auth.middleware';
import * as analyticsService from '../services/analytics.service';
import asyncWrapper from '../utils/asyncWrapper';
import ApiResponse from '../utils/apiResponse';

export const getAnalytics = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const userId = String(req.user!.id);
  const analytics = await analyticsService.getAnalytics(userId);
  return ApiResponse.success(res, analytics, 'Analytics fetched successfully');
});

export const getStreaks = asyncWrapper(async (req: CustomRequest, res: Response) => {
  const userId = String(req.user!.id);
  const streaks = await analyticsService.getStreaks(userId);
  return ApiResponse.success(res, streaks, 'Streaks fetched successfully');
});
