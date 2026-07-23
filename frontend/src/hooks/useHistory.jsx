import { useState, useEffect, useCallback, useRef } from 'react';
import { fetchHistory, deleteAnalysisRecord } from '../services/api';

export function useHistory(initialSearch = '', initialSort = 'date_desc', initialFilter = 'All') {
  const [historyList, setHistoryList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState(initialSearch);
  const [sort, setSort] = useState(initialSort);
  const [filter, setFilter] = useState(initialFilter);
  const debounceRef = useRef(null);

  const loadHistory = useCallback(async (searchVal, sortVal, filterVal) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchHistory(searchVal, sortVal, filterVal);
      setHistoryList(data.analyses || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Debounce search by 300ms; sort/filter changes fire immediately
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      loadHistory(search, sort, filter);
    }, 300);
    return () => clearTimeout(debounceRef.current);
  }, [search, sort, filter, loadHistory]);

  const deleteAnalysis = async (recordId, e) => {
    if (e) e.stopPropagation();
    try {
      const success = await deleteAnalysisRecord(recordId);
      if (success) {
        setHistoryList(prev => prev.filter(item => item.id !== recordId));
      }
    } catch (err) {
      setError(err.message);
    }
  };

  return {
    historyList,
    loading,
    error,
    search, setSearch,
    sort, setSort,
    filter, setFilter,
    deleteAnalysis,
    refreshHistory: loadHistory
  };
}
