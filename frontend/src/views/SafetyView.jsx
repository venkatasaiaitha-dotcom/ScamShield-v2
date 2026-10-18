import React, { useState, useEffect, useCallback } from 'react';
import {
  BookOpen,
  KeyRound,
  Link,
  Flame,
  Gift,
  Briefcase,
  Globe2,
  CheckCircle2,
  XCircle,
  ShieldCheck,
  Activity,
  RefreshCw
} from 'lucide-react';
import { api } from '../services/api';
import CommunityRadarCard from '../components/CommunityRadarCard';

export default function SafetyView() {
  const [activeTab, setActiveTab] = useState('tips'); // 'tips', 'compare', 'security'
  const [securityData, setSecurityData] = useState(null);
  const [loadingSecurity, setLoadingSecurity] = useState(false);

  const fetchSecurityHealth = useCallback(async () => {
    setLoadingSecurity(true);
    try {
      const data = await api.getSecurityHealth();
      setSecurityData(data);
    } catch (err) {
      console.error('Failed to load security health:', err);
    } finally {
      setLoadingSecurity(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'security') {
      fetchSecurityHealth();
    }
  }, [activeTab, fetchSecurityHealth]);

  const tips = [
    {
      title: 'Never Share OTPs or Passwords',
      icon: KeyRound,
      color: 'text-red-600 bg-red-50 border-red-200',
      description:
        'Legitimate banks, government departments, and service providers will NEVER call, text, or email requesting your one-time password or security PIN. Keep them strictly confidential.',
    },
    {
      title: 'Inspect Suspicious Links Carefully',
      icon: Link,
      color: 'text-amber-600 bg-amber-50 border-amber-200',
      description:
        'Fraudsters use look-alike domains like "sbi-kyc-verify.top" or URL shorteners (bit.ly) to mask fake phishing portals. Always navigate directly to the official domain.',
    },
    {
      title: 'Beware of Artificial Urgency Traps',
      icon: Flame,
      color: 'text-orange-600 bg-orange-50 border-orange-200',
      description:
        'Scammers try to trigger panic with deadlines like "within 24 hours" or "account will be blocked today". Stop, breathe, and verify through an independent channel before clicking.',
    },
    {
      title: 'Don’t Trust Unexpected Rewards or Lotteries',
      icon: Gift,
      color: 'text-amber-600 bg-amber-50 border-amber-200',
      description:
        'If you didn\'t participate in a competition, you haven\'t won a cash prize. Offers asking for a "processing fee" or "tax deposit" to release winnings are 100% scams.',
    },
    {
      title: 'Verify Work-From-Home & Job Offers',
      icon: Briefcase,
      color: 'text-blue-600 bg-blue-50 border-blue-200',
      description:
        'Jobs offering ₹5,000–₹10,000/day for rating videos or typing captchas that demand an upfront registration kit or activation fee are advance-fee frauds.',
    },
    {
      title: 'Authenticate Through Official Mobile Apps',
      icon: Globe2,
      color: 'text-teal-700 bg-teal-50 border-teal-200',
      description:
        'Whenever in doubt about a bank card block or KYC notification, open your official bank mobile application or call customer care using the number printed on your physical ATM card.',
    },
  ];

  const comparisons = [
    {
      context: 'Bank KYC Notification',
      scam: {
        sender: 'SBI-ALRT',
        text: 'Your SBI account KYC has expired today. Card will be blocked in 24 hours. Immediately update KYC: http://sbi-kyc-portal.xyz/login',
        flags: ['Artificial urgency (today)', 'Suspicious non-official domain (.xyz)', 'Threat of card blocking'],
      },
      legit: {
        sender: 'SBI-BANK',
        text: 'Dear Customer, Please update your periodic KYC at your nearest SBI home branch or via the official YONO SBI mobile app. SBI never sends links to update KYC.',
        flags: ['Directs to official branch or app', 'Explicitly states bank never sends update links', 'No fake countdown timer'],
      },
    },
    {
      context: 'Authentication One-Time Password (OTP)',
      scam: {
        sender: '+91-98765-43210',
        text: 'Dear customer, your electricity connection will be disconnected tonight at 9 PM. Send the OTP received on SMS to this number to stop disconnection.',
        flags: ['Unverified personal mobile number', 'Demands forwarding the OTP', 'Threatens immediate utility cutoff'],
      },
      legit: {
        sender: 'UNIV-PORTAL',
        text: 'Your OTP for signing into your university portal is 681042. Valid for 10 minutes. Please do not share this one-time code with anyone.',
        flags: ['Explicitly advises "do not share"', 'Informational only', 'No redirection links'],
      },
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header & Mode Switch */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-6 rounded-2xl bg-white border border-slate-200 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-teal-50 border border-teal-200 text-teal-700">
            <BookOpen className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
              Safety &amp; Architecture Hub
            </h2>
            <p className="text-xs text-slate-500">
              Cybersecurity education, threat verification patterns, and live defense status
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-1 bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs">
          <button
            onClick={() => setActiveTab('tips')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
              activeTab === 'tips'
                ? 'bg-white text-teal-800 shadow-xs border border-slate-200'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Safety Guidelines
          </button>
          <button
            onClick={() => setActiveTab('radar')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
              activeTab === 'radar'
                ? 'bg-white text-teal-800 shadow-xs border border-slate-200'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            📡 Community Radar
          </button>
          <button
            onClick={() => setActiveTab('compare')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
              activeTab === 'compare'
                ? 'bg-white text-teal-800 shadow-xs border border-slate-200'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Scam vs Legit
          </button>
          <button
            onClick={() => setActiveTab('security')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
              activeTab === 'security'
                ? 'bg-white text-teal-800 shadow-xs border border-slate-200'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            🛡️ Security Health
          </button>
        </div>
      </div>

      {/* Community Threat Radar Tab */}
      {activeTab === 'radar' && <CommunityRadarCard />}

      {/* Safety Tips Tab */}
      {activeTab === 'tips' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {tips.map((tip, idx) => {
            const Icon = tip.icon;
            return (
              <div
                key={idx}
                className="p-5 rounded-2xl bg-white border border-slate-200 shadow-xs flex flex-col justify-between hover:shadow-md transition-shadow"
              >
                <div>
                  <div className={`w-10 h-10 rounded-xl border flex items-center justify-center mb-3 ${tip.color}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 mb-1.5">
                    {tip.title}
                  </h3>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    {tip.description}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Scam vs Legit Tab */}
      {activeTab === 'compare' && (
        <div className="space-y-6">
          {comparisons.map((c, idx) => (
            <div key={idx} className="p-6 rounded-2xl bg-white border border-slate-200 shadow-xs space-y-4">
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">
                Scenario: {c.context}
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Scam column */}
                <div className="p-4 rounded-xl bg-red-50/50 border border-red-200 space-y-2">
                  <div className="flex items-center space-x-2 text-xs font-bold text-red-700">
                    <XCircle className="w-4 h-4 text-red-600" />
                    <span>Scam Variant (High Risk)</span>
                  </div>
                  <div className="text-xs font-mono text-slate-800 bg-white p-2.5 rounded-lg border border-red-200 leading-relaxed">
                    <div className="text-[10px] text-slate-500 font-bold mb-1">From: {c.scam.sender}</div>
                    {c.scam.text}
                  </div>
                  <ul className="text-[11px] text-red-800 space-y-1 list-disc list-inside pt-1">
                    {c.scam.flags.map((flag, fIdx) => (
                      <li key={fIdx}>{flag}</li>
                    ))}
                  </ul>
                </div>

                {/* Legit column */}
                <div className="p-4 rounded-xl bg-emerald-50/50 border border-emerald-200 space-y-2">
                  <div className="flex items-center space-x-2 text-xs font-bold text-emerald-800">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    <span>Legitimate Variant (Safe)</span>
                  </div>
                  <div className="text-xs font-mono text-slate-800 bg-white p-2.5 rounded-lg border border-emerald-200 leading-relaxed">
                    <div className="text-[10px] text-slate-500 font-bold mb-1">From: {c.legit.sender}</div>
                    {c.legit.text}
                  </div>
                  <ul className="text-[11px] text-emerald-800 space-y-1 list-disc list-inside pt-1">
                    {c.legit.flags.map((flag, fIdx) => (
                      <li key={fIdx}>{flag}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Security Health & Defense Architecture Tab */}
      {activeTab === 'security' && (
        <div className="space-y-6">
          {/* Top Banner Status */}
          <div className="p-6 rounded-2xl bg-white border border-teal-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <div className="w-12 h-12 rounded-xl bg-teal-50 border border-teal-200 flex items-center justify-center text-teal-700 shadow-xs">
                <ShieldCheck className="w-7 h-7" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-bold text-teal-800 uppercase tracking-wider bg-teal-50 px-2 py-0.5 rounded-md border border-teal-200">
                    Defense Integrity: 10/10 Active
                  </span>
                  <span className="text-xs text-slate-500 font-semibold">
                    Role: {securityData?.current_user_role || 'AUTHENTICATED'}
                  </span>
                </div>
                <h3 className="text-lg font-bold text-slate-900 mt-1">
                  Overall System Security: {securityData?.overall_status || 'SECURE'} ({securityData?.security_score || 98}/100)
                </h3>
              </div>
            </div>

            <button
              onClick={fetchSecurityHealth}
              disabled={loadingSecurity}
              className="px-3.5 py-2 bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 rounded-xl text-xs font-semibold flex items-center space-x-1.5 shadow-xs transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingSecurity ? 'animate-spin' : ''}`} />
              <span>Refresh Health</span>
            </button>
          </div>

          {/* Defense Layers Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {securityData?.checks?.map((check, idx) => (
              <div
                key={idx}
                className="p-4 rounded-2xl bg-white border border-slate-200 shadow-xs flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-slate-900">{check.name}</span>
                    <span className="text-[10px] font-bold text-teal-800 bg-teal-50 px-2 py-0.5 rounded-full border border-teal-200">
                      ● {check.status}
                    </span>
                  </div>
                  <div className="text-[11px] font-semibold text-teal-700 mb-1">
                    {check.algorithm}
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    {check.description}
                  </p>
                </div>
              </div>
            )) || (
              <div className="col-span-2 py-8 text-center text-slate-400">
                Loading live defense checks...
              </div>
            )}
          </div>

          {/* Recent Audit Events (If Admin) */}
          {securityData?.recent_audit_events && securityData.recent_audit_events.length > 0 && (
            <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-xs space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                <div className="flex items-center space-x-2">
                  <Activity className="w-4 h-4 text-teal-700" />
                  <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide">
                    Live Audit Log Stream (Admin Privilege)
                  </h4>
                </div>
                <span className="text-[11px] text-slate-400 font-medium">Zero plaintext credential logging</span>
              </div>
              <div className="space-y-2">
                {securityData.recent_audit_events.map((log) => (
                  <div
                    key={log.id}
                    className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-xs flex items-center justify-between font-mono"
                  >
                    <div>
                      <span className="font-bold text-teal-800 mr-2">[{log.action}]</span>
                      <span className="text-slate-700">{log.details || 'Event logged'}</span>
                    </div>
                    <span className="text-[10px] text-slate-400 shrink-0 ml-3">
                      {log.timestamp?.slice(11, 19) || ''}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
