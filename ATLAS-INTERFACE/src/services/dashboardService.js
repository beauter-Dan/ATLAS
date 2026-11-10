import { request } from './apiClient.js';
import { endpoints } from './contract.js';
import { toUiDashboard } from './mappers.js';

export const getDashboardSummary = async () => toUiDashboard((await request(endpoints.dashboardSummary)).data);
