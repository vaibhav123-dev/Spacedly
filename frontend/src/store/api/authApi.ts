import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { API_BASE_URL } from '@/config/app';

export const authApi = createApi({
  reducerPath: 'authApi',
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE_URL,
    credentials: 'include',
  }),
  tagTypes: ['User'],
  endpoints: (builder) => ({
    login: builder.mutation({
      query: (credentials: { email: string; password: string }) => ({
        url: '/auth/login',
        method: 'POST',
        body: credentials,
      }),
    }),
    register: builder.mutation({
      query: (userData: { email: string; password: string; name: string }) => ({
        url: '/auth/register',
        method: 'POST',
        body: userData,
      }),
    }),
    logout: builder.mutation({
      query: () => ({
        url: '/auth/logout',
        method: 'POST',
      }),
    }),
    forgotPassword: builder.mutation({
      query: (email: { email: string }) => ({
        url: '/auth/forgot-password',
        method: 'POST',
        body: email,
      }),
    }),
    resetPassword: builder.mutation({
      query: (data: { token: string; password: string }) => ({
        url: '/auth/reset-password',
        method: 'POST',
        body: data,
      }),
    }),
    getMe: builder.query({
      query: () => '/user/me',
      providesTags: ['User'],
    }),
    toggle2FA: builder.mutation({
      query: (data: { is_Enabled: boolean }) => ({
        url: '/user/enabled-2fa',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['User'],
    }),
    setPassword: builder.mutation({
      query: (data: { password: string }) => ({
        url: '/user/set-password',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['User'],
    }),
  }),
});

export const {
  useLoginMutation,
  useRegisterMutation,
  useLogoutMutation,
  useForgotPasswordMutation,
  useResetPasswordMutation,
  useGetMeQuery,
  useToggle2FAMutation,
  useSetPasswordMutation,
} = authApi;
