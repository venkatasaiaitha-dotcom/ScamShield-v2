import React from 'react';
import { ShieldAlert, AlertTriangle, AlertOctagon, X, Network } from 'lucide-react';

export default function AlertModal({ alert, onClose, onViewDetails }) {
  if (!alert) return null;

  const isHighRisk = alert.risk_level === 'HIGH' || alert.risk_score >= 70;
  const riskColor = isHighRisk ? 'text-red-600' : 'text-amber-600';
  const borderColor = isHighRisk ? 'border-red-200' : 'border-amber-200';
  const badgeBg = isHighRisk ? 'bg-red-50 text-red-700 border-red-200' : 'bg-amber-50 text-amber-700 border-amber-200';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-in fade-in duration-200">
      <div className={`w-full max-w-lg rounded-2xl bg-white border ${borderColor} shadow-2xl p-6 relative overflow-hidden`}>
        {/* Top color indicator bar */}
        <div className={`absolute top-0 left-0 right-0 h-1.5 ${isHighRisk ? 'bg-red-600' : 'bg-amber-500'}`} />

        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2.5 rounded-xl border ${badgeBg}`}>
              {isHighRisk ? (
                <AlertOctagon className="w-6 h-6 text-red-600 animate-pulse" />
              ) : (
                <AlertTriangle className="w-6 h-6 text-amber-600" />
              )}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-bold tracking-wider uppercase text-slate-500">
                  🛡️ ScamShield Alert
                </span>
                <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${badgeBg}`}>
                  {isHighRisk ? '⚠️ HIGH-RISK MESSAGE' : '⚠️ SUSPICIOUS MESSAGE'}
                </span>
              </div>
              <div className="text-xl font-bold text-slate-900 mt-0.5">
                Risk Score: <span className={riskColor}>{alert.risk_score}/100</span>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Message preview snippet */}
        <div className="mt-4 p-3.5 rounded-xl bg-slate-50 border border-slate-200">
          <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1">
            <span>From: <strong className="text-slate-800">{alert.sender}</strong></span>
            <span className="font-semibold text-teal-800 bg-teal-50 px-1.5 py-0.5 rounded border border-teal-200 text-[10px]">{alert.source || 'Incoming'}</span>
          </div>
          <p className="text-xs text-slate-700 italic line-clamp-2">
            "{alert.content_preview || alert.summary}"
          </p>
        </div>

        {/* Human summary */}
        <p className="mt-3.5 text-sm text-slate-800 leading-relaxed font-medium">
          {alert.summary || 'This incoming message contains characteristics commonly associated with scam attempts.'}
        </p>

        {/* Reasons bullets */}
        {alert.reasons && alert.reasons.length > 0 && (
          <div className="mt-3.5 space-y-1.5 bg-slate-50 p-3.5 rounded-xl border border-slate-200">
            <span className="text-[11px] font-bold text-slate-600 uppercase tracking-wider block">
              Why did ScamShield warn me?
            </span>
            <ul className="space-y-1.5">
              {alert.reasons.slice(0, 3).map((r, i) => (
                <li key={i} className="text-xs text-slate-700 flex items-start space-x-2">
                  <span className={`mt-1 w-1.5 h-1.5 rounded-full shrink-0 ${isHighRisk ? 'bg-red-500' : 'bg-amber-500'}`} />
                  <span>
                    <strong className="text-slate-900">{r.title || r}:</strong> {r.description || ''}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Action Center - Don'ts & Dos */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
          <div className="p-3 rounded-xl bg-red-50/80 border border-red-200 text-red-900">
            <span className="font-bold flex items-center gap-1 text-red-700 mb-1">
              ❌ What NOT to do
            </span>
            <ul className="list-disc list-inside space-y-0.5 text-[11px] text-red-800">
              <li>Do not click any embedded links</li>
              <li>Never share OTP, PIN, or passwords</li>
            </ul>
          </div>
          <div className="p-3 rounded-xl bg-teal-50/80 border border-teal-200 text-teal-900">
            <span className="font-bold flex items-center gap-1 text-teal-800 mb-1">
              ✅ Recommended Action
            </span>
            <ul className="list-disc list-inside space-y-0.5 text-[11px] text-teal-800">
              <li>Verify through official phone/app</li>
              <li>Block sender if unrecognized</li>
            </ul>
          </div>
        </div>

        {/* Bottom actions */}
        <div className="mt-5 flex items-center justify-end space-x-3 pt-3 border-t border-slate-100">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-xl transition-colors cursor-pointer"
          >
            Dismiss
          </button>
          {onViewDetails && (
            <button
              onClick={() => {
                onClose();
                onViewDetails(alert);
              }}
              className="px-4 py-2 text-xs font-semibold bg-teal-700 hover:bg-teal-800 text-white rounded-xl shadow-xs transition-colors flex items-center space-x-1.5 cursor-pointer"
            >
              <Network className="w-3.5 h-3.5" />
              <span>Investigate Connected Evidence</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
