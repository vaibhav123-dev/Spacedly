import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import userReducer from './slices/userSlice';
import taskReducer from './slices/taskSlice';
import reminderReducer from './slices/reminderSlice';
import analyticsReducer from './slices/analyticsSlice';
import notificationReducer from './slices/notificationSlice';
import uiReducer from './slices/uiSlice';
import { authApi } from './api/authApi';
import { taskApi } from './api/taskApi';
import { reminderApi } from './api/reminderApi';
import { analyticsApi } from './api/analyticsApi';
import { notificationApi } from './api/notificationApi';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    user: userReducer,
    task: taskReducer,
    reminder: reminderReducer,
    analytics: analyticsReducer,
    notification: notificationReducer,
    ui: uiReducer,
    [authApi.reducerPath]: authApi.reducer,
    [taskApi.reducerPath]: taskApi.reducer,
    [reminderApi.reducerPath]: reminderApi.reducer,
    [analyticsApi.reducerPath]: analyticsApi.reducer,
    [notificationApi.reducerPath]: notificationApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(
      authApi.middleware,
      taskApi.middleware,
      reminderApi.middleware,
      analyticsApi.middleware,
      notificationApi.middleware
    ),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
