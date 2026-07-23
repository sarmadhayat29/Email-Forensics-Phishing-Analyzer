import React, { createContext, useContext, useState, useEffect } from 'react';
import { getMe } from '../services/api';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const checkSession = async () => {
      try {
        if (localStorage.getItem('token')) {
          const data = await getMe();
          if (data.authenticated) {
            setUser(data.user);
          } else {
            localStorage.removeItem('token');
            setUser(null);
          }
        }
      } catch (err) {
        console.error("Session check failed", err);
        localStorage.removeItem('token');
        setUser(null);
      } finally {
        setAuthLoading(false);
      }
    };
    
    checkSession();

    const handleUnauthorized = () => {
      setUser(null);
      localStorage.removeItem('token');
      navigate('/login');
    };
    
    window.addEventListener('auth-unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth-unauthorized', handleUnauthorized);
  }, [navigate]);

  const loginUser = (token, userData) => {
    localStorage.setItem('token', token);
    setUser(userData);
    navigate('/dashboard');
  };

  const logoutUser = () => {
    localStorage.removeItem('token');
    setUser(null);
    navigate('/login');
  };

  const value = {
    user,
    authLoading,
    loginUser,
    logoutUser
  };

  if (authLoading) {
    return <div className="h-screen w-full bg-soc-bg"></div>;
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => {
  return useContext(AuthContext);
};
