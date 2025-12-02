import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { API_BASE_URL } from '@/config/app';
import { Reminder } from '../slices/reminderSlice';

export const reminderApi = createApi({
  reducerPath: 'reminderApi',
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE_URL,
    credentials: 'include',
  }),
  tagTypes: ['Reminder'],
  endpoints: (builder) => ({
    getReminders: builder.query<{ reminders: Reminder[] }, void>({
      query: () => '/reminders',
      providesTags: ['Reminder'],
      transformResponse: (response: any) => response.data || response,
    }),
    getTaskReminders: builder.query<Reminder[], string>({
      query: (taskId) => `/tasks/${taskId}/reminders`,
      providesTags: ['Reminder'],
      transformResponse: (response: any) => response.data?.reminders || response,
    }),
    createReminder: builder.mutation({
      query: (reminder: Omit<Reminder, 'id' | 'createdAt'>) => ({
        url: '/reminders',
        method: 'POST',
        body: reminder,
      }),
      invalidatesTags: ['Reminder'],
    }),
    updateReminder: builder.mutation({
      query: ({ id, ...reminder }: Partial<Reminder> & { id: string }) => ({
        url: `/reminders/${id}`,
        method: 'PUT',
        body: reminder,
      }),
      invalidatesTags: ['Reminder'],
    }),
    deleteReminder: builder.mutation({
      query: (id: string) => ({
        url: `/reminders/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Reminder'],
    }),
  }),
});

export const {
  useGetRemindersQuery,
  useGetTaskRemindersQuery,
  useCreateReminderMutation,
  useUpdateReminderMutation,
  useDeleteReminderMutation,
} = reminderApi;
