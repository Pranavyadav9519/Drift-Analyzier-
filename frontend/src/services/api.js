// api.js — Axios instance with auth token injection
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sz_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default api;
