import { request } from './apiClient.js';
import { endpoints } from './contract.js';

export const listTargets = () => request(endpoints.targets);
export const getTarget = (id) => request(endpoints.target(id));
export const createTarget = (data) => request(endpoints.targets, { method: 'POST', body: data });
export const updateTarget = (id, data) => request(endpoints.target(id), { method: 'PUT', body: data });
