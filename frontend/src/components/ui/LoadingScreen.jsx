import React from 'react';
import { Loader2 } from 'lucide-react';

export default function LoadingScreen({ message = "Loading..." }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-emerald-500">
      <Loader2 className="w-8 h-8 animate-spin mb-4" />
      <p className="text-xs font-mono uppercase tracking-widest">{message}</p>
    </div>
  );
}
