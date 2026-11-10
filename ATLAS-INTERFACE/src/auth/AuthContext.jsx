import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { env } from '../config/env.js';
import { mockUser } from '../services/mock/data.js';
import { onAuthLost } from '../services/apiClient.js';
import * as authService from '../services/authService.js';

export const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

const START = env.useMock ? { status: 'authenticated', user: mockUser, notice: null } : { status: 'anonymous', user: null, notice: null };

export function AuthProvider({ children }) {
  const [state, setState] = useState(START);

  // The API client tells us when the refresh token is rejected: drop to the sign-in screen with an explanation.
  useEffect(() => {
    onAuthLost(() => setState({ status: 'anonymous', user: null, notice: 'Your session expired. Please sign in again.' }));
    return () => onAuthLost(null);
  }, []);

  const login = useCallback(async (credentials) => {
    const user = await authService.login(credentials);
    setState({ status: 'authenticated', user, notice: null });
  }, []);

  const logout = useCallback(async () => {
    await authService.logout();
    setState({ status: 'anonymous', user: null, notice: null });
  }, []);

  const value = useMemo(() => ({ ...state, login, logout }), [state, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
