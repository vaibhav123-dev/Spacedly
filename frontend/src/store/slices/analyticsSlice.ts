import { createSlice, PayloadAction } from '@reduxjs/toolkit';

export interface AnalyticsData {
  totalTasks: number;
  completedReminders: number;
  overdueReminders: number;
  upcomingReminders: number;
  activeStreak: number;
  longestStreak: number;
  dailyData: Array<{ date: string; completed: number }>;
  weeklyData: Array<{ week: string; completed: number }>;
  categoryData: Array<{ category: string; count: number }>;
}

interface AnalyticsState {
  data: AnalyticsData | null;
}

const initialState: AnalyticsState = {
  data: null,
};

const analyticsSlice = createSlice({
  name: 'analytics',
  initialState,
  reducers: {
    setAnalytics: (state, action: PayloadAction<AnalyticsData>) => {
      state.data = action.payload;
    },
  },
});

export const { setAnalytics } = analyticsSlice.actions;
export default analyticsSlice.reducer;
