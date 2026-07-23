import React, { useState } from 'react';
import { Download, AlertTriangle } from 'lucide-react';
import { downloadReport } from '../../services/api';

export default function DownloadReportButton({ 
  fileId, 
  type = 'pdf', 
  className = '', 
  children, 
  title = '',
  onClick
}) {
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState(null);

  const handleDownload = async (e) => {
    e.stopPropagation();
    if (onClick) onClick(e);
    
    if (isDownloading) return;
    
    setIsDownloading(true);
    setDownloadError(null);
    try {
      await downloadReport(fileId, type);
    } catch (err) {
      console.error('Download failed:', err);
      setDownloadError(err.message || 'Download failed');
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <>
      <button 
        onClick={handleDownload} 
        className={`transition ${className} ${isDownloading ? 'opacity-50 cursor-not-allowed' : ''}`}
        title={title}
        disabled={isDownloading}
      >
        {children || <Download className="w-4 h-4" />}
      </button>
      {downloadError && (
        <span className="flex items-center gap-1 text-xs text-red-400 font-mono mt-1">
          <AlertTriangle className="w-3 h-3" />{downloadError}
        </span>
      )}
    </>
  );
}
