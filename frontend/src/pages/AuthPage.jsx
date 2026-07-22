import React, { useState } from 'react';
import { Shield, Mail, Lock, ArrowRight, Loader2 } from 'lucide-react';
import { login, signup } from '../services/api';

export default function AuthPage({ onAuthSuccess }) {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const data = isLogin ? await login(email, password) : await signup(email, password);
      localStorage.setItem('token', data.access_token);
      onAuthSuccess(data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#060907] flex flex-col items-center justify-center p-4 selection:bg-emerald-500/30">
      
      <div className="w-full max-w-md space-y-8">
        
        {/* Header */}
        <div className="flex flex-col items-center text-center space-y-4">
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-2xl text-emerald-400 shadow-[0_0_40px_-10px_rgba(16,185,129,0.3)]">
            <Shield className="w-10 h-10" />
          </div>
          <div>
            <h1 className="text-3xl font-extrabold text-slate-100 tracking-tight">SOC Workspace</h1>
            <p className="text-emerald-400/80 font-mono text-xs mt-2 uppercase tracking-widest">
              {isLogin ? 'Analyst Authentication' : 'Analyst Registration'}
            </p>
          </div>
        </div>

        {/* Form Card */}
        <div className="bg-[#0B0F0D] border border-emerald-900/40 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
          
          {/* Subtle background glow */}
          <div className="absolute -top-24 -right-24 w-48 h-48 bg-emerald-500/10 rounded-full blur-3xl" />
          <div className="absolute -bottom-24 -left-24 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl" />

          <form onSubmit={handleSubmit} className="relative z-10 space-y-6">
            
            {error && (
              <div className="p-4 bg-red-950/40 border border-red-900/60 rounded-xl text-red-400 text-xs text-center">
                {error}
              </div>
            )}

            <div className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-[11px] font-mono uppercase text-slate-400 ml-1">Email Address</label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input 
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-[#121814] border border-emerald-900/30 rounded-xl py-3 pl-11 pr-4 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition"
                    placeholder="analyst@soc.local"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-[11px] font-mono uppercase text-slate-400 ml-1">Password</label>
                <div className="relative">
                  <Lock className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input 
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-[#121814] border border-emerald-900/30 rounded-xl py-3 pl-11 pr-4 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition"
                    placeholder="••••••••"
                  />
                </div>
              </div>
            </div>

            <button 
              type="submit" 
              disabled={loading}
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold py-3.5 rounded-xl transition flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : (isLogin ? 'Authenticate' : 'Create Account')}
              {!loading && <ArrowRight className="w-4 h-4" />}
            </button>
          </form>
        </div>

        {/* Footer Toggle */}
        <div className="text-center">
          <button 
            onClick={() => { setIsLogin(!isLogin); setError(null); }}
            className="text-slate-400 hover:text-emerald-400 text-xs font-mono transition"
          >
            {isLogin ? 'Need an account? Register here.' : 'Already have an account? Log in.'}
          </button>
        </div>

      </div>
    </div>
  );
}
