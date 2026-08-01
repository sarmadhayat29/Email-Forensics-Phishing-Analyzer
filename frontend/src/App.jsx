import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './hooks/useAuth';

import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import UploadPage from './pages/UploadPage';
import HistoryPage from './pages/HistoryPage';
import InvestigationScreen from './pages/InvestigationScreen';
import AboutPage from './pages/AboutPage';
import AuthPage from './pages/AuthPage';

const ProtectedRoute = ({ children }) => {
  const { user, authLoading } = useAuth();
  if (authLoading) {
    return <div className="h-screen w-full bg-soc-bg" />;
  }
  if (!user) return <Navigate to="/login" replace />;
  return children;
};

const PublicRoute = ({ children }) => {
  const { user, authLoading } = useAuth();
  if (authLoading) {
    return <div className="h-screen w-full bg-soc-bg" />;
  }
  if (user) return <Navigate to="/dashboard" replace />;
  return children;
};

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<PublicRoute><AuthPage /></PublicRoute>} />
      <Route path="/signup" element={<PublicRoute><AuthPage /></PublicRoute>} />
      
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="upload" element={<UploadPage />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="analysis/:id" element={<InvestigationScreen />} />
        <Route path="about" element={<AboutPage />} />
      </Route>
      
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}
