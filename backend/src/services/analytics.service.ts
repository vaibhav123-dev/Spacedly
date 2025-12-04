import { Op } from 'sequelize';
import Task from '../models/task.model';
import Reminder from '../models/reminder.model';
import ApiError from '../utils/apiError';
import HTTP_STATUS from '../constants';
import { cacheService } from './cache.service';

interface DailyData {
  date: string;
  completed: number;
}

interface WeeklyData {
  week: string;
  completed: number;
}

interface CategoryData {
  category: string;
  count: number;
  percent: number;
}

interface AnalyticsData {
  totalTasks: number;
  completedReminders: number;
  upcomingReminders: number;
  overdueReminders: number;
  dailyData: DailyData[];
  weeklyData: WeeklyData[];
  categoryData: CategoryData[];
}

export const getAnalytics = async (userId: string): Promise<AnalyticsData> => {
  try {
    // Check cache first
    const cacheKey = `analytics:${userId}`;
    const cached = await cacheService.get(cacheKey);
    
    if (cached) {
      console.log('[Analytics] Serving from cache');
      return JSON.parse(cached);
    }
    
    const now = new Date();
    
    // Get total tasks
    const totalTasks = await Task.count({
      where: { userId },
    });

    // Get reminder statistics
    const completedReminders = await Reminder.count({
      where: {
        userId,
        status: 'completed',
      },
    });

    const upcomingReminders = await Reminder.count({
      where: {
        userId,
        status: 'pending',
        scheduledAt: {
          [Op.gt]: now,
        },
      },
    });

    const overdueReminders = await Reminder.count({
      where: {
        userId,
        status: 'pending',
        scheduledAt: {
          [Op.lt]: now,
        },
      },
    });

    // Get daily data for the last 7 days
    const dailyData = await getDailyData(userId);

    // Get weekly data for the last 4 weeks
    const weeklyData = await getWeeklyData(userId);

    // Get category distribution
    const categoryData = await getCategoryData(userId);

    const analyticsData = {
      totalTasks,
      completedReminders,
      upcomingReminders,
      overdueReminders,
      dailyData,
      weeklyData,
      categoryData,
    };
    
    // Cache for 5 minutes (300 seconds)
    await cacheService.set(cacheKey, JSON.stringify(analyticsData), 300);
    
    return analyticsData;
  } catch (error) {
    console.error('[Analytics Error]:', error);
    throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to fetch analytics');
  }
};

const getDailyData = async (userId: string): Promise<DailyData[]> => {
  const now = new Date();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(now.getDate() - 7);

  const dailyData: DailyData[] = [];

  for (let i = 0; i < 7; i++) {
    const date = new Date(now);
    date.setDate(now.getDate() - i);
    const startOfDay = new Date(date.setHours(0, 0, 0, 0));
    const endOfDay = new Date(date.setHours(23, 59, 59, 999));

    const completed = await Reminder.count({
      where: {
        userId,
        status: 'completed',
        scheduledAt: {
          [Op.between]: [startOfDay, endOfDay],
        },
      },
    });

    dailyData.unshift({
      date: startOfDay.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      completed,
    });
  }

  return dailyData;
};

const getWeeklyData = async (userId: string): Promise<WeeklyData[]> => {
  const now = new Date();
  const weeklyData: WeeklyData[] = [];

  for (let i = 0; i < 4; i++) {
    const weekEnd = new Date(now);
    weekEnd.setDate(now.getDate() - (i * 7));
    weekEnd.setHours(23, 59, 59, 999);

    const weekStart = new Date(weekEnd);
    weekStart.setDate(weekEnd.getDate() - 6);
    weekStart.setHours(0, 0, 0, 0);

    const completed = await Reminder.count({
      where: {
        userId,
        status: 'completed',
        scheduledAt: {
          [Op.between]: [weekStart, weekEnd],
        },
      },
    });

    weeklyData.unshift({
      week: `Week ${4 - i}`,
      completed,
    });
  }

  return weeklyData;
};

const getCategoryData = async (userId: string): Promise<CategoryData[]> => {
  const tasks = await Task.findAll({
    where: { userId },
    attributes: ['category'],
    raw: true,
  });

  const categoryCounts: { [key: string]: number } = {};
  const totalCount = tasks.length;

  tasks.forEach((task: any) => {
    const category = task.category || 'Uncategorized';
    categoryCounts[category] = (categoryCounts[category] || 0) + 1;
  });

  const categoryData: CategoryData[] = Object.entries(categoryCounts).map(([category, count]) => ({
    category,
    count,
    percent: totalCount > 0 ? count / totalCount : 0,
  }));

  return categoryData;
};

export const getStreaks = async (userId: string) => {
  try {
    const now = new Date();
    let activeStreak = 0;
    let longestStreak = 0;
    let currentStreak = 0;

    // Get all completed reminders ordered by date
    const completedReminders = await Reminder.findAll({
      where: {
        userId,
        status: 'completed',
      },
      order: [['scheduledAt', 'DESC']],
      raw: true,
    });

    if (completedReminders.length === 0) {
      return { active: 0, longest: 0 };
    }

    // Group by day
    const dayMap = new Map<string, number>();
    completedReminders.forEach((reminder: any) => {
      const date = new Date(reminder.scheduledAt);
      const dayKey = date.toISOString().split('T')[0];
      dayMap.set(dayKey, (dayMap.get(dayKey) || 0) + 1);
    });

    const sortedDays = Array.from(dayMap.keys()).sort().reverse();

    // Calculate active streak
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(now.setDate(now.getDate() - 1)).toISOString().split('T')[0];

    if (sortedDays[0] === today || sortedDays[0] === yesterday) {
      activeStreak = 1;
      let checkDate = new Date(sortedDays[0]);

      for (let i = 1; i < sortedDays.length; i++) {
        checkDate.setDate(checkDate.getDate() - 1);
        const expectedDate = checkDate.toISOString().split('T')[0];

        if (sortedDays[i] === expectedDate) {
          activeStreak++;
        } else {
          break;
        }
      }
    }

    // Calculate longest streak
    currentStreak = 1;
    longestStreak = 1;
    let prevDate = new Date(sortedDays[0]);

    for (let i = 1; i < sortedDays.length; i++) {
      const currentDate = new Date(sortedDays[i]);
      const diffTime = Math.abs(prevDate.getTime() - currentDate.getTime());
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

      if (diffDays === 1) {
        currentStreak++;
        longestStreak = Math.max(longestStreak, currentStreak);
      } else {
        currentStreak = 1;
      }

      prevDate = currentDate;
    }

    return {
      active: activeStreak,
      longest: longestStreak,
    };
  } catch (error) {
    console.error('[Streaks Error]:', error);
    throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to fetch streaks');
  }
};
