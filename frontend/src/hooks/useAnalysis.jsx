import { useState, useEffect } from 'react';
import { fetchAnalysis, deleteAnalysisRecord } from '../services/api';

export function useAnalysis(id) {
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!id) return;
    
    const loadAnalysis = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchAnalysis(id);
        setFinding(data.finding);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    loadAnalysis();
  }, [id]);

  const removeAnalysis = async () => {
    try {
      return await deleteAnalysisRecord(id);
    } catch (err) {
      setError(err.message);
      return false;
    }
  };

  return { finding, loading, error, removeAnalysis, setError };
}
