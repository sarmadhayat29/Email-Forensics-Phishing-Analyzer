const API_BASE = import.meta.env.VITE_API_URL || "";

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return token ? { 'Authorization': `Bearer ${token}` } : {};
};

const handleResponse = async (response) => {
  if (response.status === 401) {
    localStorage.removeItem('token');
    window.dispatchEvent(new Event('auth-unauthorized'));
    throw new Error("Session expired or unauthorized. Please log in again.");
  }
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || "An error occurred.");
  }
  return response.json();
};

export const login = async (email, password) => {
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return handleResponse(response);
};

export const signup = async (email, password, fullName = '') => {
  const response = await fetch(`${API_BASE}/api/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, full_name: fullName || undefined }),
  });
  return handleResponse(response);
};

export const getMe = async () => {
  const response = await fetch(`${API_BASE}/api/auth/me`, {
    headers: getAuthHeaders(),
  });
  return handleResponse(response);
};

export const uploadEmailPayload = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await fetch(`${API_BASE}/api/upload`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
  });
  return handleResponse(response);
};

export const analyzePayload = async (fileId) => {
  const response = await fetch(`${API_BASE}/api/analyze/${fileId}`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  return handleResponse(response);
};

export const fetchHistory = async (search, sort, filter) => {
  const queryParams = new URLSearchParams({
    search: search || '',
    sort: sort || 'date_desc',
    risk_level: filter || 'All'
  });
  
  const response = await fetch(`${API_BASE}/api/analyses?${queryParams.toString()}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse(response);
};

export const fetchAnalysis = async (recordId) => {
  const response = await fetch(`${API_BASE}/api/analyses/${recordId}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse(response);
};

export const deleteAnalysisRecord = async (recordId) => {
  const response = await fetch(`${API_BASE}/api/analyses/${recordId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (response.status === 401) {
    localStorage.removeItem('token');
    window.dispatchEvent(new Event('auth-unauthorized'));
    throw new Error("Session expired or unauthorized.");
  }
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || "Delete failed.");
  }
  return true;
};

export const downloadReport = async (fileId, type) => {
  const response = await fetch(`${API_BASE}/api/report/${fileId}/download/${type}`, {
    headers: getAuthHeaders(),
  });
  if (response.status === 401) {
    localStorage.removeItem('token');
    window.dispatchEvent(new Event('auth-unauthorized'));
    throw new Error("Session expired or unauthorized.");
  }
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || "Download failed.");
  }
  
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `investigation_${fileId.substring(0, 8)}.report.${type}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
};
