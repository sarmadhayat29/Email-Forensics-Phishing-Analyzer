import React from 'react';

export default function ErrorBanner({ error, onDismiss }) {
  if (!error) return null;
  
  return (
    <div className="mb-6 p-4 bg-red-950/60 border border-red-800 rounded-2xl text-red-200 text-xs flex items-center justify-between">
      <span>⚠️ {error}</span>
      {onDismiss && (
        <button onClick={onDismiss} className="font-bold text-red-300">Dismiss</button>
      )}
    </div>
  );
}
