import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { API_BASE_URL } from '@/config/app';
import { Task, TaskAttachment } from '../slices/taskSlice';

// Transform backend attachment data to frontend format
const transformAttachment = (attachment: any): TaskAttachment => ({
  id: attachment.id,
  name: attachment.originalName || attachment.name,
  size: attachment.fileSize || attachment.size,
  type: attachment.fileType || attachment.type,
  url: attachment.fileUrl || attachment.url,
});

// Transform task data with attachments
const transformTask = (task: any): Task => ({
  ...task,
  attachments: task.attachments?.map(transformAttachment) || [],
});

export const taskApi = createApi({
  reducerPath: 'taskApi',
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE_URL,
    credentials: 'include',
  }),
  tagTypes: ['Task', 'Analytics'],
  endpoints: (builder) => ({
    getTasks: builder.query<{ tasks: Task[] }, void>({
      query: () => '/tasks',
      providesTags: ['Task'],
      transformResponse: (response: any) => {
        const data = response.data || response;
        return {
          ...data,
          tasks: data.tasks?.map(transformTask) || [],
        };
      },
    }),
    getTask: builder.query<Task, string>({
      query: (id) => `/tasks/${id}`,
      providesTags: ['Task'],
      transformResponse: (response: any) => {
        const task = response.data?.task || response;
        return transformTask(task);
      },
    }),
    createTask: builder.mutation({
      query: (task: Omit<Task, 'id' | 'createdAt' | 'updatedAt'>) => ({
        url: '/tasks',
        method: 'POST',
        body: task,
      }),
      transformResponse: (response: any) => {
        const task = response.data?.task || response;
        return transformTask(task);
      },
      invalidatesTags: ['Task', 'Analytics'],
    }),
    updateTask: builder.mutation({
      query: ({ id, ...task }: Partial<Task> & { id: string }) => ({
        url: `/tasks/${id}`,
        method: 'PUT',
        body: task,
      }),
      invalidatesTags: ['Task'],
    }),
    deleteTask: builder.mutation({
      query: (id: string) => ({
        url: `/tasks/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Task', 'Analytics'],
    }),
    uploadAttachments: builder.mutation({
      query: ({ taskId, files }: { taskId: string; files: File[] }) => {
        const formData = new FormData();
        files.forEach((file) => {
          formData.append('files', file);
        });
        return {
          url: `/attachments/${taskId}`,
          method: 'POST',
          body: formData,
        };
      },
      invalidatesTags: ['Task'],
    }),
  }),
});

export const {
  useGetTasksQuery,
  useGetTaskQuery,
  useCreateTaskMutation,
  useUpdateTaskMutation,
  useDeleteTaskMutation,
  useUploadAttachmentsMutation,
} = taskApi;
