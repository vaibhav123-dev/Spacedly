import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { API_BASE_URL } from '@/config/app';
import { AnalyticsData } from '../slices/analyticsSlice';

export const analyticsApi = createApi({
  reducerPath: 'analyticsApi',
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE_URL,
    credentials: 'include',
  }),
  endpoints: (builder) => ({
    getAnalytics: builder.query<AnalyticsData, void>({
      query: () => '/analytics',
    }),
    getStreaks: builder.query<{ active: number; longest: number }, void>({
      query: () => '/analytics/streaks',
    }),
  }),
});

export const { useGetAnalyticsQuery, useGetStreaksQuery } = analyticsApi;
