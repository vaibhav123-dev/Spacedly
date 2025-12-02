import { store } from './store';
import { setCredentials, setLoading } from './slices/authSlice';
import axiosInstance from '@/services/axios';
import { API_BASE_URL } from '@/config/app';

export const initializeAuth = async () => {
  store.dispatch(setLoading(true));
  
  // Check if API URL is configured
  if (!API_BASE_URL || API_BASE_URL.includes('localhost')) {
    console.log('No backend API configured. Skipping auth initialization.');
    store.dispatch(setLoading(false));
    return;
  }
  
  try {
    // Try to get current user from backend
    const response = await axiosInstance.get('/user/me');
    
    if (response.data) {
      store.dispatch(setCredentials({
        accessToken: 'from-cookie', // Token is in HTTP-only cookie
        user: response.data,
      }));
    }
  } catch (error) {
    // User is not authenticated or backend is not available
    console.log('Auth initialization failed:', error);
    store.dispatch(setLoading(false));
  }
};
