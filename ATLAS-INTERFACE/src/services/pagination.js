import { request } from './apiClient.js';

const PAGE = 200;     // backend maximum
const MAX_PAGES = 50;

/** Collects every page of a list endpoint. `params` are plain query values. */
export async function fetchAll(path, params = {}) {
  const out = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const qs = new URLSearchParams({ ...params, page: String(page), page_size: String(PAGE) });
    const res = await request(`${path}?${qs}`);
    out.push(...res.data);
    if (out.length >= res.meta.total || res.data.length === 0) break;
  }
  return out;
}
