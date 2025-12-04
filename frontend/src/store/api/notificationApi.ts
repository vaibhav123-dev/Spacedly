import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { API_BASE_URL } from '@/config/app';
import { Notification } from '../slices/notificationSlice';

export const notificationApi = createApi({
  reducerPath: 'notificationApi',
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE_URL,
    credentials: 'include',
  }),
  tagTypes: ['Notification'],
  endpoints: (builder) => ({
    getNotifications: builder.query<Notification[], void>({
      query: () => '/notifications',
      providesTags: ['Notification'],
      transformResponse: (response: any) => response.data?.notifications || response,
    }),
    getUnreadCount: builder.query<number, void>({
      query: () => '/notifications/count',
      providesTags: ['Notification'],
      transformResponse: (response: any) => response.data?.count || 0,
    }),
    markAsRead: builder.mutation({
      query: (id: string) => ({
        url: `/notifications/${id}/read`,
        method: 'PATCH',
      }),
      invalidatesTags: ['Notification'],
    }),
  }),
});

export const { useGetNotificationsQuery, useGetUnreadCountQuery, useMarkAsReadMutation } = notificationApi;
