import React, { useState, useEffect } from 'react';
import {
  Radio,
  Users,
  ThumbsUp,
  ShieldAlert,
  PlusCircle,
  Clock,
  CheckCircle2,
  Loader2
} from 'lucide-react';
import { api } from '../services/api';

export default function CommunityRadarCard() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [upvotedIds, setUpvotedIds] = useState(new Set());
  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newSender, setNewSender] = useState('');
  const [newCategory, setNewCategory] = useState('PHISHING');
  const [submitting, setSubmitting] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  useEffect(() => {
    let isMounted = true;
    async function loadFeed() {
      try {
        const data = await api.getCommunityFeed();
        if (isMounted) setReports(data || []);
      } catch (err) {
        console.error('Failed to load community feed:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    loadFeed();
    return () => { isMounted = false; };
  }, []);

  const handleUpvote = async (id) => {
    if (upvotedIds.has(id)) return;
    try {
      const res = await api.upvoteCommunityReport(id);
      setUpvotedIds((prev) => new Set([...prev, id]));
      setReports((prev) =>
        prev.map((r) => (r.id === id ? { ...r, upvotes: res.upvotes || r.upvotes + 1 } : r))
      );
    } catch (err) {
      console.error('Failed to upvote report:', err);
    }
  };

  const handleCreateReport = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    setSubmitting(true);
    try {
      await api.reportToCommunity({
        threat_title: newTitle.trim(),
        sender: newSender.trim() || 'Unknown',
        category: newCategory,
        risk_score: 88,
        risk_level: 'HIGH',
        indicators: ['Community Verified', 'Active Phishing Campaign'],
      });
      setSubmitSuccess(true);
      setTimeout(() => {
        setSubmitSuccess(false);
        setShowSubmitModal(false);
        setNewTitle('');
        setNewSender('');
      }, 1500);

      // Refresh list
      const fresh = await api.getCommunityFeed();
      setReports(fresh || []);
    } catch (err) {
      console.error('Failed to submit report:', err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden transition-all">
      {/* Header */}
      <div className="p-5 sm:p-6 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-teal-50 border border-teal-200 flex items-center justify-center text-teal-700 shadow-xs">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base sm:text-lg font-bold text-slate-900">
                Community Threat Radar
              </h2>
              <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full bg-teal-50 text-teal-800 border border-teal-200">
                Live Intel Feed
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Crowdsourced scam intelligence reported by verified users across the network
            </p>
          </div>
        </div>

        <button
          onClick={() => setShowSubmitModal(true)}
          className="px-3.5 py-1.5 rounded-xl bg-teal-700 hover:bg-teal-800 text-white text-xs font-semibold flex items-center space-x-1.5 shadow-xs transition-colors self-start sm:self-auto cursor-pointer"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span>Report New Scam</span>
        </button>
      </div>

      {/* Reports List */}
      <div className="p-5 sm:p-6 space-y-3">
        {loading ? (
          <div className="py-8 text-center text-slate-400">
            <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-teal-600" />
            <span className="text-xs">Connecting to Community Radar Stream...</span>
          </div>
        ) : reports.length > 0 ? (
          reports.map((item) => {
            const hasUpvoted = upvotedIds.has(item.id);
            return (
              <div
                key={item.id}
                className="p-4 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-300 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xs"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-50 text-red-700 border border-red-200">
                      {item.risk_level} RISK • {item.risk_score}/100
                    </span>
                    <span className="text-xs font-semibold text-slate-800">
                      via {item.sender}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-slate-900">
                    {item.threat_title}
                  </h3>

                  {item.indicators && item.indicators.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-0.5">
                      {item.indicators.map((ind, i) => (
                        <span
                          key={i}
                          className="text-[10px] bg-white border border-slate-200 text-slate-600 px-2 py-0.5 rounded-md font-medium"
                        >
                          {ind}
                        </span>
                      ))}
                    </div>
                  )}

                  <div className="text-[11px] text-slate-400 flex items-center space-x-1 pt-1">
                    <Clock className="w-3 h-3" />
                    <span>Reported {item.reported_at}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 self-end sm:self-center shrink-0">
                  <button
                    onClick={() => handleUpvote(item.id)}
                    disabled={hasUpvoted}
                    className={`px-3 py-1.5 rounded-xl border text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer ${
                      hasUpvoted
                        ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                        : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-100 hover:border-slate-300'
                    }`}
                  >
                    <ThumbsUp className={`w-3.5 h-3.5 ${hasUpvoted ? 'text-emerald-600' : 'text-slate-400'}`} />
                    <span>{item.upvotes} {hasUpvoted ? 'Confirmed' : 'Confirm'}</span>
                  </button>
                </div>
              </div>
            );
          })
        ) : (
          <div className="py-8 text-center text-slate-400">
            <Users className="w-8 h-8 mx-auto mb-2 text-slate-300" />
            <span className="text-xs">No active community alerts yet.</span>
          </div>
        )}
      </div>

      {/* Modal for reporting a new scam */}
      {showSubmitModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-xl border border-slate-200 space-y-4">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-teal-50 text-teal-700">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-900">
                Report Threat to Community Radar
              </h3>
            </div>

            <form onSubmit={handleCreateReport} className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-700 block mb-1">
                  Threat Subject / Scam Summary *
                </label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Fake Credit Card Reward Phishing SMS"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 focus:outline-none focus:border-teal-600"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-700 block mb-1">
                  Sender Identity / Phone / Email
                </label>
                <input
                  type="text"
                  value={newSender}
                  onChange={(e) => setNewSender(e.target.value)}
                  placeholder="e.g. +91-98765-XXXXX or HDFC-REWARDS"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 focus:outline-none focus:border-teal-600"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-700 block mb-1">
                  Scam Category
                </label>
                <select
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 focus:outline-none focus:border-teal-600"
                >
                  <option value="FAKE_KYC_PHISHING">Fake KYC Phishing</option>
                  <option value="BANK_IMPERSONATION">Bank Impersonation</option>
                  <option value="LOTTERY_SCAM">Lottery / Prize Bait</option>
                  <option value="TASK_ADVANCE_FEE">Job / Task Fee Fraud</option>
                  <option value="UTILITY_IMPERSONATION">Utility Disconnection Threat</option>
                  <option value="QUISHING_QR_PHISHING">QR Code (Quishing)</option>
                </select>
              </div>

              {submitSuccess && (
                <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-700 rounded-xl text-xs flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Report submitted successfully! Thank you for protecting the community.</span>
                </div>
              )}

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowSubmitModal(false)}
                  className="px-3.5 py-1.5 text-xs text-slate-600 hover:bg-slate-100 rounded-xl cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 bg-teal-700 hover:bg-teal-800 text-white rounded-xl text-xs font-bold shadow-xs cursor-pointer"
                >
                  {submitting ? 'Submitting...' : 'Publish to Radar'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
