import axios from 'axios';
import { API_BASE_URL, API_ENDPOINTS } from '@/config/app';

const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Important for cookies
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
axiosInstance.interceptors.request.use(
  (config) => {
    // Token is in HTTP-only cookie, no need to add here
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If no backend is available, just reject
    if (!error.response) {
      return Promise.reject(error);
    }

    // If error is 401 and we haven't tried to refresh yet
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Try to refresh the token
        await axios.post(
          `${API_BASE_URL}${API_ENDPOINTS.REFRESH_TOKEN}`,
          {},
          { withCredentials: true }
        );

        // Retry the original request
        return axiosInstance(originalRequest);
      } catch (refreshError) {
        // Refresh failed, redirect to login
        const publicRoutes = ['/login', '/signup', '/', '/forgot-password', '/reset-password', '/verify-otp'];
        const isPublicRoute = publicRoutes.some(route => window.location.pathname.startsWith(route));
        
        if (!isPublicRoute) {
          window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default axiosInstance;
