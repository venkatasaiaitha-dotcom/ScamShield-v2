import React, { useState, useEffect } from 'react';
import {
  Mail,
  Send,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  ShieldCheck,
  ArrowRight,
  Info
} from 'lucide-react';
import { api } from '../services/api';

export default function GmailConnectorCard({ onMessageAnalyzed, onOpenDetail }) {
  const [activeTab, setActiveTab] = useState('input'); // 'input' or 'oauth'
  const [gmailStatus, setGmailStatus] = useState({ connected: false, email: '', oauth_configured: false });

  // Direct Input Form State
  const [sender, setSender] = useState('Security Alert <service@paypaI-billing-verify.com>');
  const [subject, setSubject] = useState('Urgent: Your account access has been restricted');
  const [body, setBody] = useState(
    'Dear Customer,\n\nWe detected unauthorized login attempts from an unknown device. To protect your funds, your account has been temporarily restricted.\n\nPlease verify your identity immediately: http://account-recovery-portal.xyz/secure/kyc\n\nFailure to verify within 24 hours will result in permanent suspension.'
  );
  const [loadingInput, setLoadingInput] = useState(false);
  const [feedback, setFeedback] = useState(null);

  useEffect(() => {
    let isMounted = true;
    async function loadGmailStatus() {
      try {
        const status = await api.getGmailStatus();
        if (isMounted) setGmailStatus(status);
      } catch (err) {
        console.error('Error loading Gmail status:', err);
      }
    }
    loadGmailStatus();
    return () => { isMounted = false; };
  }, []);

  const handleDirectInspect = async (e) => {
    e.preventDefault();
    if (!body.trim()) return;

    setLoadingInput(true);
    setFeedback(null);
    try {
      const res = await api.inputGmailMessage(
        sender.trim() || 'Inbound Email',
        subject.trim() || '(No Subject)',
        body.trim()
      );

      if (onMessageAnalyzed) onMessageAnalyzed(res);
      setFeedback({
        type: 'success',
        message: `Gmail message inspected! Result: ${res.risk_level} RISK (Score: ${res.risk_score}/100)`,
        analysis: res,
      });
    } catch (err) {
      setFeedback({ type: 'error', message: err.message || 'Failed to inspect message' });
    } finally {
      setLoadingInput(false);
    }
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden transition-all">
      {/* Top Banner Header */}
      <div className="p-5 sm:p-6 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-teal-50 border border-teal-200 flex items-center justify-center text-teal-700 shadow-xs">
            <Mail className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base sm:text-lg font-bold text-slate-900">
                Gmail Inbound Inspector
              </h2>
              <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full bg-teal-50 text-teal-800 border border-teal-200">
                Email Integration
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Proactive email inspection, phishing lure detection &amp; zero plaintext credential storage
            </p>
          </div>
        </div>

        {/* Tab switch */}
        <div className="flex items-center bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs">
          <button
            type="button"
            onClick={() => setActiveTab('input')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
              activeTab === 'input'
                ? 'bg-white text-teal-800 shadow-xs border border-slate-200'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Direct Inspection Mode
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('oauth')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
              activeTab === 'oauth'
                ? 'bg-white text-teal-800 shadow-xs border border-slate-200'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            OAuth 2.0 Integration
          </button>
        </div>
      </div>

      <div className="p-5 sm:p-6">
        {/* Direct Inbound Mode Tab */}
        {activeTab === 'input' && (
          <div>
            <div className="mb-4 p-3 bg-teal-50/70 border border-teal-200/80 rounded-xl text-xs text-teal-900 flex items-start space-x-2">
              <Sparkles className="w-4 h-4 text-teal-700 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">Real-Time Inbound Inspection: </span>
                Simulates real-world email delivery straight into ScamShield. The AI agent extracts URLs, assesses brand impersonation, evaluates urgency, and notifies you immediately.
              </div>
            </div>

            <form onSubmit={handleDirectInspect} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Sender (Header From)
                  </label>
                  <input
                    type="text"
                    required
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    placeholder="e.g., service@bank-security.com"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-teal-600 focus:bg-white transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Subject Line
                  </label>
                  <input
                    type="text"
                    required
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="e.g., Action Required: Verify Account"
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-teal-600 focus:bg-white transition-colors"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Email Content / Body (URLs are automatically scanned)
                </label>
                <textarea
                  rows={4}
                  required
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder="Paste or write incoming email message..."
                  className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs sm:text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-teal-600 focus:bg-white transition-colors font-mono leading-relaxed resize-y"
                />
              </div>

              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                <span className="text-xs text-slate-500 flex items-center space-x-1.5">
                  <ShieldCheck className="w-4 h-4 text-teal-600" />
                  <span>Inspected server-side with SSRF filters &amp; heuristic safety checks</span>
                </span>

                <button
                  type="submit"
                  disabled={loadingInput}
                  className="w-full sm:w-auto px-5 py-2.5 bg-teal-700 hover:bg-teal-800 disabled:opacity-50 text-white font-semibold rounded-xl text-xs sm:text-sm transition-colors shadow-xs flex items-center justify-center space-x-2 cursor-pointer"
                >
                  <Send className="w-4 h-4" />
                  <span>{loadingInput ? 'Analyzing Threat...' : 'Send & Inspect Inbound Email'}</span>
                </button>
              </div>
            </form>

            {/* Inspection Feedback Result */}
            {feedback && (
              <div
                className={`mt-4 p-4 rounded-xl border text-xs sm:text-sm flex items-start justify-between gap-3 ${
                  feedback.type === 'success'
                    ? 'bg-teal-50 border-teal-200 text-teal-900'
                    : 'bg-red-50 border-red-200 text-red-900'
                }`}
              >
                <div className="flex items-start space-x-2">
                  {feedback.type === 'success' ? (
                    <CheckCircle2 className="w-5 h-5 text-teal-700 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <span className="font-bold">{feedback.message}</span>
                    {feedback.analysis && (
                      <p className="mt-1 text-xs text-slate-600">
                        {feedback.analysis.summary}
                      </p>
                    )}
                  </div>
                </div>

                {feedback.type === 'error' && (
                  <button
                    type="button"
                    onClick={handleDirectInspect}
                    className="shrink-0 px-3 py-1.5 bg-white border border-red-300 text-red-700 rounded-lg text-xs font-semibold hover:bg-red-50 transition-colors shadow-xs cursor-pointer"
                  >
                    Retry Inspection
                  </button>
                )}

                {feedback.analysis && onOpenDetail && (
                  <button
                    onClick={() => onOpenDetail(feedback.analysis)}
                    className="shrink-0 px-3 py-1.5 bg-white border border-teal-300 text-teal-800 rounded-lg text-xs font-semibold hover:bg-teal-50 transition-colors flex items-center space-x-1 shadow-xs cursor-pointer"
                  >
                    <span>View Report</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        {/* OAuth Tab */}
        {activeTab === 'oauth' && (
          <div className="space-y-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
              <div className="flex items-center space-x-2">
                <Info className="w-5 h-5 text-teal-700 shrink-0" />
                <h3 className="text-sm font-bold text-slate-900">Google OAuth 2.0 Integration Status</h3>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                ScamShield adheres strictly to Google security guidelines. Automated background inbox reading requires official Google Cloud OAuth verification (Client ID and Secret).
              </p>
              
              <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900 flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0" />
                <span>
                  {gmailStatus.oauth_configured
                    ? 'Google OAuth credentials detected in environment.'
                    : 'Google OAuth credentials not configured in environment. Direct Inbound Mode is active and recommended for testing.'}
                </span>
              </div>

              <div className="text-xs text-slate-500 pt-2 border-t border-slate-200">
                To connect a live Gmail inbox in production, supply <code className="bg-slate-200 text-slate-800 px-1 py-0.5 rounded font-mono">GOOGLE_CLIENT_ID</code> and <code className="bg-slate-200 text-slate-800 px-1 py-0.5 rounded font-mono">GOOGLE_CLIENT_SECRET</code> in the environment variables.
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
