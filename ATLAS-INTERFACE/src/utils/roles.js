const LEVEL = { viewer: 0, analyst: 1, approver: 2, admin: 3 };
/** UI hint only: the server enforces roles on every request. */
export const hasRole = (user, minimum) => (LEVEL[user?.role] ?? -1) >= LEVEL[minimum];
