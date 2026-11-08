import { request } from './apiClient.js';
import { endpoints } from './contract.js';

export const getDashboardSummary = () => request(endpoints.dashboardSummary);
