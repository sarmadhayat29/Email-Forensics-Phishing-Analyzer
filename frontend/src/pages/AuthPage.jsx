import React, { useMemo, useState, useEffect } from 'react';
import { useLocation, Link } from 'react-router-dom';
import {
  Shield, Mail, Lock, User, ArrowRight, Loader2, Eye, EyeOff, CheckCircle2,
} from 'lucide-react';
import { login, signup } from '../services/api';
import { useAuth } from '../hooks/useAuth';
import {
  validateLoginForm,
  validateSignupForm,
  passwordStrength,
} from '../utils/authValidation';

const inputClass =
  'w-full bg-soc-card border border-emerald-900/30 rounded-xl py-3 pl-11 pr-12 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition';
const inputErrorClass = 'border-red-800/70 focus:border-red-500 focus:ring-red-500';

function FieldError({ id, message }) {
  if (!message) return null;
  return (
    <p id={id} role="alert" className="text-[11px] text-red-400 ml-1 pt-1">
      {message}
    </p>
  );
}

function PasswordToggle({ visible, onToggle, label }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-label={visible ? `Hide ${label}` : `Show ${label}`}
      aria-pressed={visible}
      className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 rounded-lg text-slate-500 hover:text-emerald-400 hover:bg-emerald-500/10 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
    >
      {visible ? <EyeOff className="w-4 h-4" aria-hidden /> : <Eye className="w-4 h-4" aria-hidden />}
    </button>
  );
}

function StrengthMeter({ password }) {
  const { level, label } = passwordStrength(password);
  if (!password) return null;
  const widths = { weak: 'w-1/3', fair: 'w-2/3', strong: 'w-full' };
  const colors = {
    weak: 'bg-red-500',
    fair: 'bg-amber-400',
    strong: 'bg-emerald-500',
  };
  return (
    <div className="space-y-1.5 pt-1" aria-live="polite">
      <div className="h-1.5 w-full rounded-full bg-soc-card border border-emerald-950 overflow-hidden">
        <div className={`h-full transition-all duration-300 ${widths[level]} ${colors[level]}`} />
      </div>
      <p className="text-[10px] font-mono text-slate-500">
        Password strength: <span className="text-slate-300">{label}</span>
      </p>
    </div>
  );
}

export default function AuthPage() {
  const { loginUser } = useAuth();
  const location = useLocation();
  const isLogin = location.pathname !== '/signup';

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [touched, setTouched] = useState({});
  const [submitAttempted, setSubmitAttempted] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setError(null);
    setSuccess(null);
    setSubmitAttempted(false);
    setTouched({});
    setPassword('');
    setConfirmPassword('');
    setShowPassword(false);
    setShowConfirmPassword(false);
  }, [isLogin]);

  const validation = useMemo(() => {
    if (isLogin) return validateLoginForm({ email, password });
    return validateSignupForm({ fullName, email, password, confirmPassword });
  }, [isLogin, fullName, email, password, confirmPassword]);

  const showFieldError = (field) =>
    (submitAttempted || touched[field]) ? validation.errors[field] : null;

  const markTouched = (field) => setTouched((prev) => ({ ...prev, [field]: true }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitAttempted(true);
    setError(null);
    setSuccess(null);

    if (!validation.isValid) return;

    setLoading(true);
    try {
      if (isLogin) {
        const data = await login(email.trim(), password);
        loginUser(data.access_token, data.user);
        return;
      }

      const data = await signup(email.trim(), password, fullName.trim());
      setSuccess('Account created successfully.');
      // Brief success flash, then auto sign-in (API already returns a token).
      window.setTimeout(() => {
        loginUser(data.access_token, data.user);
      }, 700);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const heading = isLogin ? 'Welcome Back' : 'Create Your Account';
  const subtitle = isLogin
    ? 'Sign in to access your Email Forensics dashboard.'
    : 'Create an account to start analyzing emails and generating forensic reports.';

  return (
    <div className="min-h-screen bg-soc-black flex flex-col items-center justify-center p-4 sm:p-6 selection:bg-emerald-500/30">
      <div className="w-full max-w-md space-y-6 sm:space-y-8">
        <div className="flex flex-col items-center text-center space-y-4">
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-2xl text-emerald-400 shadow-[0_0_40px_-10px_rgba(16,185,129,0.3)]">
            <Shield className="w-10 h-10" aria-hidden />
          </div>
          <div>
            <p className="text-emerald-400/80 font-mono text-[10px] uppercase tracking-widest mb-2">
              Email Forensics Platform
            </p>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100 tracking-tight">
              {heading}
            </h1>
            <p className="text-slate-400 text-sm mt-2 max-w-sm mx-auto leading-relaxed">
              {subtitle}
            </p>
          </div>
        </div>

        <div className="bg-soc-bg border border-emerald-900/40 rounded-3xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
          <div className="absolute -top-24 -right-24 w-48 h-48 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute -bottom-24 -left-24 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

          <form onSubmit={handleSubmit} className="relative z-10 space-y-5" noValidate>
            {error && (
              <div role="alert" className="p-3.5 bg-red-950/40 border border-red-900/60 rounded-xl text-red-400 text-xs text-center">
                {error}
              </div>
            )}
            {success && (
              <div role="status" className="p-3.5 bg-emerald-950/40 border border-emerald-800/60 rounded-xl text-emerald-300 text-xs text-center flex items-center justify-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden />
                {success}
              </div>
            )}

            <div className="space-y-4">
              {!isLogin && (
                <div className="space-y-1.5">
                  <label htmlFor="auth-fullname" className="text-[11px] font-mono uppercase text-slate-400 ml-1">
                    Full Name
                  </label>
                  <div className="relative">
                    <User className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden />
                    <input
                      id="auth-fullname"
                      name="fullName"
                      type="text"
                      autoComplete="name"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      onBlur={() => markTouched('fullName')}
                      aria-invalid={!!showFieldError('fullName')}
                      aria-describedby={showFieldError('fullName') ? 'auth-fullname-error' : undefined}
                      className={`${inputClass} ${showFieldError('fullName') ? inputErrorClass : ''}`}
                      placeholder="Jane Analyst"
                    />
                  </div>
                  <FieldError id="auth-fullname-error" message={showFieldError('fullName')} />
                </div>
              )}

              <div className="space-y-1.5">
                <label htmlFor="auth-email" className="text-[11px] font-mono uppercase text-slate-400 ml-1">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden />
                  <input
                    id="auth-email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    onBlur={() => markTouched('email')}
                    aria-invalid={!!showFieldError('email')}
                    aria-describedby={showFieldError('email') ? 'auth-email-error' : undefined}
                    className={`${inputClass} pr-4 ${showFieldError('email') ? inputErrorClass : ''}`}
                    placeholder="analyst@company.com"
                  />
                </div>
                <FieldError id="auth-email-error" message={showFieldError('email')} />
              </div>

              <div className="space-y-1.5">
                <label htmlFor="auth-password" className="text-[11px] font-mono uppercase text-slate-400 ml-1">
                  Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden />
                  <input
                    id="auth-password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete={isLogin ? 'current-password' : 'new-password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onBlur={() => markTouched('password')}
                    aria-invalid={!!showFieldError('password')}
                    aria-describedby={showFieldError('password') ? 'auth-password-error' : undefined}
                    className={`${inputClass} ${showFieldError('password') ? inputErrorClass : ''}`}
                    placeholder="••••••••"
                  />
                  <PasswordToggle
                    visible={showPassword}
                    onToggle={() => setShowPassword((v) => !v)}
                    label="password"
                  />
                </div>
                <FieldError id="auth-password-error" message={showFieldError('password')} />
                {!isLogin && <StrengthMeter password={password} />}
              </div>

              {!isLogin && (
                <div className="space-y-1.5">
                  <label htmlFor="auth-confirm" className="text-[11px] font-mono uppercase text-slate-400 ml-1">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden />
                    <input
                      id="auth-confirm"
                      name="confirmPassword"
                      type={showConfirmPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      onBlur={() => markTouched('confirmPassword')}
                      aria-invalid={!!showFieldError('confirmPassword')}
                      aria-describedby={showFieldError('confirmPassword') ? 'auth-confirm-error' : undefined}
                      className={`${inputClass} ${showFieldError('confirmPassword') ? inputErrorClass : ''}`}
                      placeholder="••••••••"
                    />
                    <PasswordToggle
                      visible={showConfirmPassword}
                      onToggle={() => setShowConfirmPassword((v) => !v)}
                      label="confirm password"
                    />
                  </div>
                  <FieldError id="auth-confirm-error" message={showFieldError('confirmPassword')} />
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading || !validation.isValid}
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold py-3.5 rounded-xl transition flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:ring-offset-2 focus-visible:ring-offset-soc-bg"
            >
              {loading ? (
                <Loader2 className="w-5 h-5 animate-spin" aria-hidden />
              ) : (
                <>
                  {isLogin ? 'Sign In' : 'Create Account'}
                  <ArrowRight className="w-4 h-4" aria-hidden />
                </>
              )}
            </button>
          </form>
        </div>

        <div className="text-center">
          {isLogin ? (
            <p className="text-slate-400 text-xs">
              Need an account?{' '}
              <Link
                to="/signup"
                className="text-emerald-400 hover:text-emerald-300 font-semibold transition focus:outline-none focus-visible:underline"
              >
                Create Account
              </Link>
            </p>
          ) : (
            <p className="text-slate-400 text-xs">
              Already have an account?{' '}
              <Link
                to="/login"
                className="text-emerald-400 hover:text-emerald-300 font-semibold transition focus:outline-none focus-visible:underline"
              >
                Sign In
              </Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
