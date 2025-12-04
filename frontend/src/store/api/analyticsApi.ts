import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { API_BASE_URL } from '@/config/app';
import { AnalyticsData } from '../slices/analyticsSlice';

export const analyticsApi = createApi({
  reducerPath: 'analyticsApi',
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE_URL,
    credentials: 'include',
  }),
  tagTypes: ['Analytics'],
  endpoints: (builder) => ({
    getAnalytics: builder.query<AnalyticsData, void>({
      query: () => '/analytics',
      transformResponse: (response: any) => response.data || response,
      providesTags: ['Analytics'],
      // Refetch when navigating back to the page after 60 seconds
      keepUnusedDataFor: 60,
    }),
    getStreaks: builder.query<{ active: number; longest: number }, void>({
      query: () => '/analytics/streaks',
      transformResponse: (response: any) => response.data || response,
      providesTags: ['Analytics'],
      // Refetch when navigating back to the page after 60 seconds
      keepUnusedDataFor: 60,
    }),
  }),
});

export const { useGetAnalyticsQuery, useGetStreaksQuery } = analyticsApi;
