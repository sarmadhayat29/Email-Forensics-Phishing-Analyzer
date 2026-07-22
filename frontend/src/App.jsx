import React, { useState, useRef, useEffect } from 'react';
import { UploadCloud, Shield, LayoutDashboard, Clock, Search, Info, Download, FileCode, LogOut } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import UploadPage from './pages/UploadPage';
import HistoryPage from './pages/HistoryPage';
import InvestigationScreen from './pages/InvestigationScreen';
import AboutPage from './pages/AboutPage';
import AuthPage from './pages/AuthPage';
import { uploadEmailPayload, analyzePayload, fetchHistory, fetchAnalysis, deleteAnalysisRecord, getMe, downloadReport } from './services/api';

export default function App() {
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  const [activePage, setActivePage] = useState('dashboard');
  const [fileId, setFileId] = useState(null);
  const [filename, setFilename] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [analysisStep, setAnalysisStep] = useState(0);
  const [finding, setFinding] = useState(null);
  const [error, setError] = useState(null);

  const [historyList, setHistoryList] = useState([]);
  const [historySearch, setHistorySearch] = useState('');
  const [historySort, setHistorySort] = useState('date_desc');
  const [historyFilter, setHistoryFilter] = useState('All');

  const fileInputRef = useRef(null);

  useEffect(() => {
    const checkSession = async () => {
      try {
        if (localStorage.getItem('token')) {
          const data = await getMe();
          if (data.authenticated) {
            setUser(data.user);
          } else {
            localStorage.removeItem('token');
          }
        }
      } catch (err) {
        console.error("Session check failed", err);
      } finally {
        setAuthLoading(false);
      }
    };
    checkSession();

    const handleUnauthorized = () => {
      setUser(null);
    };
    window.addEventListener('auth-unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth-unauthorized', handleUnauthorized);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  const handleDownload = async (type) => {
    try {
      await downloadReport(fileId, type);
    } catch (err) {
      setError(err.message);
    }
  };

  const analysisSteps = [
    "Parsing Email Payload",
    "Analyzing Headers",
    "Checking Authentication",
    "Analyzing Routing",
    "Calculating Risk Score",
    "Generating Report"
  ];

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) processUpload(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) processUpload(file);
  };

  const processUpload = async (file) => {
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext !== 'eml' && ext !== 'msg') {
      setError("Invalid file format. Only .eml and .msg email files are supported.");
      return;
    }

    setError(null);
    setFilename(file.name);
    setActivePage('upload');
    setUploadProgress(0);

    const interval = setInterval(() => {
      setUploadProgress((prev) => (prev >= 90 ? 90 : prev + 30));
    }, 100);

    try {
      const data = await uploadEmailPayload(file);
      clearInterval(interval);
      setUploadProgress(100);
      setFileId(data.file_id);

      setTimeout(() => {
        runAnalysis(data.file_id, file.name);
      }, 400);

    } catch (err) {
      clearInterval(interval);
      setError(err.message);
      setActivePage('dashboard');
    }
  };

  const runAnalysis = async (fId, fName) => {
    setAnalysisStep(0);

    const stepInterval = setInterval(() => {
      setAnalysisStep((prev) => (prev >= analysisSteps.length - 1 ? prev : prev + 1));
    }, 250);

    try {
      const data = await analyzePayload(fId);
      clearInterval(stepInterval);
      setFinding(data.finding);
      setActivePage('results');
    } catch (err) {
      clearInterval(stepInterval);
      setError(err.message);
      setActivePage('dashboard');
    }
  };

  const loadHistory = async () => {
    if (!user) return;
    try {
      const data = await fetchHistory(historySearch, historySort, historyFilter);
      setHistoryList(data.analyses || []);
    } catch (err) {
      console.error(err.message);
    }
  };

  useEffect(() => {
    loadHistory();
  }, [historySearch, historySort, historyFilter, user]);

  const openPreviousAnalysis = async (recordId) => {
    setError(null);
    try {
      const data = await fetchAnalysis(recordId);
      setFileId(recordId);
      setFinding(data.finding);
      setActivePage('results');
    } catch (err) {
      setError(err.message);
    }
  };

  const deleteAnalysis = async (recordId, e) => {
    if (e) e.stopPropagation();
    try {
      const success = await deleteAnalysisRecord(recordId);
      if (success) {
        setHistoryList(prev => prev.filter(item => item.id !== recordId));
        if (fileId === recordId) {
          setFinding(null);
          setFileId(null);
          setActivePage('dashboard');
        }
      }
    } catch (err) {
      console.error(err.message);
    }
  };

  if (authLoading) return <div className="h-screen w-full bg-[#0B0F0D]"></div>;
  
  if (!user) {
    return <AuthPage onAuthSuccess={(userData) => setUser(userData)} />;
  }

  return (
    <div className="flex h-screen bg-[#0B0F0D] text-slate-100 font-sans overflow-hidden">
      
      {/* PERSISTENT SIDEBAR NAVIGATION */}
      <aside className="w-64 bg-[#090D0B] border-r border-emerald-950 flex flex-col justify-between shrink-0">
        <div>
          <div className="p-6 border-b border-emerald-950 flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-extrabold text-base leading-none text-slate-100">SOC Workspace</h1>
              <span className="text-[10px] font-mono text-cyan-400">Forensics Engine v2.0</span>
            </div>
          </div>

          <nav className="p-4 space-y-1.5">
            <button onClick={() => setActivePage('dashboard')} className={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-3 transition ${activePage === 'dashboard' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'text-slate-400 hover:bg-[#121814] hover:text-slate-200'}`}>
              <LayoutDashboard className="w-4 h-4" /> Workspace Dashboard
            </button>
            <button onClick={() => setActivePage('upload')} className={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-3 transition ${activePage === 'upload' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'text-slate-400 hover:bg-[#121814] hover:text-slate-200'}`}>
              <UploadCloud className="w-4 h-4" /> Upload &amp; Analyze
            </button>
            <button onClick={() => setActivePage('history')} className={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-3 transition ${activePage === 'history' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'text-slate-400 hover:bg-[#121814] hover:text-slate-200'}`}>
              <Clock className="w-4 h-4" /> Analysis History
            </button>
            <button onClick={() => setActivePage('results')} disabled={!finding} className={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-3 transition ${!finding ? 'opacity-40 cursor-not-allowed text-slate-600' : (activePage === 'results' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'text-slate-400 hover:bg-[#121814] hover:text-slate-200')}`}>
              <Search className="w-4 h-4" /> Investigation Screen
            </button>
            <button onClick={() => setActivePage('about')} className={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-3 transition ${activePage === 'about' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'text-slate-400 hover:bg-[#121814] hover:text-slate-200'}`}>
              <Info className="w-4 h-4" /> System Architecture
            </button>
          </nav>
        </div>
        
        <div className="p-4 border-t border-emerald-950">
          <div className="px-3 pb-3 mb-2 border-b border-emerald-950/50">
            <p className="text-[10px] font-mono text-slate-500 uppercase">Logged in as</p>
            <p className="text-xs font-bold text-slate-300 truncate" title={user.email}>{user.email}</p>
          </div>
          <button onClick={handleLogout} className="w-full px-3.5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-3 text-red-400 hover:bg-red-950/30 transition">
            <LogOut className="w-4 h-4" /> Secure Logout
          </button>
        </div>
      </aside>

      {/* MAIN WORKSPACE CONTENT */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        
        <header className="h-16 border-b border-emerald-950 bg-[#090D0B] px-8 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <h2 className="font-bold text-base text-slate-100 capitalize">{activePage.replace('-', ' ')}</h2>
            {fileId && <span className="px-2.5 py-0.5 bg-[#121814] border border-emerald-900/50 text-cyan-400 font-mono text-xs rounded">File ID: {fileId.substring(0, 8)}</span>}
          </div>

          {finding && (
            <div className="flex items-center gap-2">
              <button onClick={() => handleDownload('html')} className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 rounded-lg text-xs font-bold flex items-center gap-1.5 transition">
                <Download className="w-3.5 h-3.5" /> HTML Report
              </button>
              <button onClick={() => handleDownload('pdf')} className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 transition">
                <Download className="w-3.5 h-3.5" /> PDF Report
              </button>
              <button onClick={() => handleDownload('json')} className="px-3 py-1.5 bg-[#121814] hover:bg-slate-800 border border-emerald-900/60 rounded-lg text-xs font-bold flex items-center gap-1.5 text-slate-200 transition">
                <FileCode className="w-3.5 h-3.5" /> JSON Export
              </button>
            </div>
          )}
        </header>

        <div className="flex-1 overflow-y-auto p-8">
          
          {error && (
            <div className="mb-6 p-4 bg-red-950/60 border border-red-800 rounded-2xl text-red-200 text-xs flex items-center justify-between">
              <span>⚠️ {error}</span>
              <button onClick={() => setError(null)} className="font-bold text-red-300">Dismiss</button>
            </div>
          )}

          {activePage === 'dashboard' && (
            <Dashboard 
              historyList={historyList} 
              setActivePage={setActivePage} 
              openPreviousAnalysis={openPreviousAnalysis} 
              deleteAnalysis={deleteAnalysis} 
            />
          )}

          {activePage === 'upload' && (
            <UploadPage 
              uploadProgress={uploadProgress}
              filename={filename}
              finding={finding}
              analysisSteps={analysisSteps}
              analysisStep={analysisStep}
              fileInputRef={fileInputRef}
              handleDrop={handleDrop}
              handleFileChange={handleFileChange}
            />
          )}

          {activePage === 'history' && (
            <HistoryPage 
              historyList={historyList}
              historySearch={historySearch}
              setHistorySearch={setHistorySearch}
              historyFilter={historyFilter}
              setHistoryFilter={setHistoryFilter}
              historySort={historySort}
              setHistorySort={setHistorySort}
              openPreviousAnalysis={openPreviousAnalysis}
              deleteAnalysis={deleteAnalysis}
            />
          )}

          {activePage === 'results' && finding && (
            <InvestigationScreen finding={finding} />
          )}

          {activePage === 'about' && (
            <AboutPage />
          )}

        </div>
      </div>
    </div>
  );
}
