// API Configuration
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api';

export const API_ENDPOINTS = {
  // Auth
  LOGIN: '/auth/login',
  REGISTER: '/auth/register',
  LOGOUT: '/auth/logout',
  REFRESH_TOKEN: '/auth/refresh',
  FORGOT_PASSWORD: '/auth/forgot-password',
  RESET_PASSWORD: '/auth/reset-password',
  GOOGLE_AUTH: '/auth/google',
  
  // User
  ME: '/user/me',
  UPDATE_PROFILE: '/user/profile',
  
  // Tasks
  TASKS: '/tasks',
  TASK_BY_ID: (id: string) => `/tasks/${id}`,
  
  // Reminders
  REMINDERS: '/reminders',
  REMINDER_BY_ID: (id: string) => `/reminders/${id}`,
  TASK_REMINDERS: (taskId: string) => `/tasks/${taskId}/reminders`,
  
  // Analytics
  ANALYTICS: '/analytics',
  STREAKS: '/analytics/streaks',
  
  // Notifications
  NOTIFICATIONS: '/notifications',
  MARK_READ: (id: string) => `/notifications/${id}/read`,
};
