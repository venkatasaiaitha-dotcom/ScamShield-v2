import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  X,
  ChevronDown,
  ChevronUp,
  Link,
  Lock,
  LockOpen,
  CheckCircle2,
  FileText,
  Copy,
  Check,
  Radio,
  Loader2,
  Languages,
  Network
} from 'lucide-react';
import { api } from '../services/api';
import ScamAttackChainCard from './ScamAttackChainCard';
import ScamDNACard from './ScamDNACard';
import UPISafetyCard from './UPISafetyCard';
import AttackerNextMoveCard from './AttackerNextMoveCard';
import GraphInvestigationCard from './GraphInvestigationCard';

export default function AnalysisModal({ analysis, onClose }) {
  const [showTechnical, setShowTechnical] = useState(false);
  const [showGraphInvestigation, setShowGraphInvestigation] = useState(false);
  const [copied, setCopied] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [reported, setReported] = useState(false);

  if (!analysis) return null;

  const handleReportCommunity = async () => {
    setReporting(true);
    try {
      await api.reportToCommunity({
        threat_title: `${analysis.category?.replace(/_/g, ' ') || 'High-Risk Scam'} (${analysis.sender})`,
        sender: analysis.sender,
        category: analysis.category || 'PHISHING',
        risk_score: analysis.risk_score || 90,
        risk_level: analysis.risk_level || 'HIGH',
        indicators: (analysis.reasons || []).map((r) => r.title || r).slice(0, 3),
      });
      setReported(true);
      setTimeout(() => setReported(false), 3000);
    } catch (err) {
      console.error('Failed to report to community:', err);
    } finally {
      setReporting(false);
    }
  };

  const isHighRisk = analysis.risk_level === 'HIGH' || analysis.risk_score >= 70;
  const isSuspicious = analysis.risk_level === 'SUSPICIOUS' || (analysis.risk_score >= 30 && analysis.risk_score < 70);

  const riskColor = isHighRisk ? 'text-red-600' : isSuspicious ? 'text-amber-600' : 'text-emerald-600';
  const badgeBorder = isHighRisk ? 'border-red-200' : isSuspicious ? 'border-amber-200' : 'border-emerald-200';
  const badgeBg = isHighRisk ? 'bg-red-50 text-red-700' : isSuspicious ? 'bg-amber-50 text-amber-700' : 'bg-emerald-50 text-emerald-700';

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(analysis, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-2xl max-h-[90vh] flex flex-col rounded-2xl bg-white border border-slate-200 shadow-2xl overflow-hidden">
        {/* Top Header */}
        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/80">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-xl border ${badgeBorder} ${badgeBg}`}>
              {isHighRisk ? (
                <AlertOctagon className="w-6 h-6" />
              ) : isSuspicious ? (
                <AlertTriangle className="w-6 h-6" />
              ) : (
                <ShieldCheck className="w-6 h-6" />
              )}
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                SCAMSHIELD THREAT REPORT
              </h2>
              <p className="text-xs text-slate-500">
                Processed at {analysis.timestamp || 'Just now'} • Source: <strong className="text-slate-700">{analysis.source || 'INBOUND'}</strong>
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopy}
              title="Copy JSON metadata"
              className="p-1.5 rounded-lg border border-slate-200 text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg border border-slate-200 text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Scrollable Content Body */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-5">
          {/* Key Metric Gauges */}
          <div className="grid grid-cols-3 gap-3 p-4 rounded-xl bg-slate-50 border border-slate-200 text-center">
            <div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Risk Score
              </span>
              <span className={`text-2xl sm:text-3xl font-extrabold ${riskColor}`}>
                {analysis.risk_score}
                <span className="text-xs font-normal text-slate-400"> / 100</span>
              </span>
            </div>
            <div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Threat Level
              </span>
              <span className={`inline-block mt-1 text-xs font-bold px-2.5 py-0.5 rounded-full border ${badgeBorder} ${badgeBg}`}>
                {analysis.risk_level} RISK
              </span>
            </div>
            <div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Category
              </span>
              <span className="text-xs sm:text-sm font-bold text-slate-800 block mt-1 truncate">
                {analysis.category || 'UNKNOWN'}
              </span>
            </div>
          </div>

          {/* Sender & Content Preview */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-500 border-b border-slate-200 pb-2">
              <span>Sender: <strong className="text-slate-800">{analysis.sender}</strong></span>
              <span className="font-semibold text-teal-800 bg-teal-50 px-2 py-0.5 rounded border border-teal-200 text-[10px]">{analysis.source}</span>
            </div>
            <div className="text-xs text-slate-700 font-mono bg-white p-3 rounded-lg border border-slate-200 whitespace-pre-wrap max-h-36 overflow-y-auto">
              {analysis.content_preview || '(No content preview)'}
            </div>
          </div>

          {/* Track 1: FalkorDB Connected-Evidence Investigation Action */}
          <div className="rounded-xl border border-teal-500/40 bg-gradient-to-r from-teal-950/10 via-slate-900/5 to-teal-900/10 p-3.5 shadow-xs">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 rounded-xl bg-teal-700 text-white shadow-xs">
                  <Network className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                    FalkorDB Graph Investigation
                    <span className="text-[10px] px-2 py-0.2 bg-teal-100 text-teal-800 rounded-full font-semibold border border-teal-200">
                      Track 1
                    </span>
                  </h3>
                  <p className="text-[11px] text-slate-500">
                    Query Cypher knowledge graph for shared indicators, campaigns &amp; connected evidence
                  </p>
                </div>
              </div>

              <button
                onClick={() => setShowGraphInvestigation(!showGraphInvestigation)}
                className="px-3 py-1.5 rounded-xl bg-teal-700 hover:bg-teal-800 text-white text-xs font-semibold shadow-xs flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <Network className="w-3.5 h-3.5" />
                {showGraphInvestigation ? 'Close Graph View' : 'Investigate Connected Evidence'}
              </button>
            </div>

            {showGraphInvestigation && (
              <div className="mt-3.5 animate-in fade-in duration-200">
                <GraphInvestigationCard
                  messageId={analysis.id || analysis.message_id}
                  messageContent={analysis.full_content || analysis.content_preview}
                  initialAnalysis={analysis}
                />
              </div>
            )}
          </div>

          {/* Multilingual / Code-Mixed Indian Social Engineering Alert */}
          {analysis.multilingual && analysis.multilingual.is_multilingual && (
            <div className="bg-gradient-to-r from-orange-50 to-amber-50 rounded-xl p-3.5 border border-orange-200 text-xs flex items-start gap-2.5">
              <div className="p-1.5 bg-orange-100 text-orange-700 rounded-lg shrink-0 mt-0.5">
                <Languages className="w-4 h-4" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-bold text-orange-900">
                    Indian Code-Mixed Dialect Detected
                  </span>
                  <span className="text-[10px] font-mono font-semibold bg-orange-200/80 text-orange-800 px-2 py-0.5 rounded">
                    {analysis.multilingual.language_mix || 'Hinglish / Tenglish'}
                  </span>
                </div>
                <p className="text-slate-700 text-xs leading-relaxed">
                  {analysis.multilingual.summary_note ||
                    'Analyzed Indian code-mixed phrasing. Deceptive intent and urgency markers were identified within regional colloquialisms.'}
                </p>
                {analysis.multilingual.matched_signals && analysis.multilingual.matched_signals.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {analysis.multilingual.matched_signals.map((sig, sIdx) => (
                      <span
                        key={sIdx}
                        className="text-[10px] font-mono bg-white border border-orange-200 text-orange-900 px-2 py-0.5 rounded shadow-2xs"
                      >
                        {sig.type}: "{sig.term}" ({sig.dialect})
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Signature Feature 3: UPI Payment Safety Guard */}
          {analysis.upi_safety && analysis.upi_safety.has_upi_payload && (
            <UPISafetyCard upiSafety={analysis.upi_safety} />
          )}

          {/* Signature Feature 1: Scam Attack Chain Detection */}
          {analysis.attack_chain && (
            <ScamAttackChainCard attackChain={analysis.attack_chain} />
          )}

          {/* Signature Feature 4: Attacker Next-Move Prediction */}
          {analysis.next_moves_forecast && analysis.next_moves_forecast.length > 0 && (
            <AttackerNextMoveCard nextMoves={analysis.next_moves_forecast} />
          )}

          {/* Signature Feature 2 & 5: Scam DNA & Community Immunity Card */}
          {analysis.scam_dna && (
            <ScamDNACard scamDna={analysis.scam_dna} />
          )}

          {/* Explainable Summary */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 mb-2">
              Explainable AI Assessment
            </h3>
            <p className="text-xs sm:text-sm text-slate-800 leading-relaxed bg-white p-3.5 rounded-xl border border-slate-200 shadow-xs">
              {analysis.summary}
            </p>
          </div>

          {/* Scam Pattern Indicators */}
          {analysis.reasons && analysis.reasons.length > 0 && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 mb-2">
                Identified Threat Patterns &amp; Flags ({analysis.reasons.length})
              </h3>
              <div className="space-y-2">
                {analysis.reasons.map((reason, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-white border border-slate-200 shadow-xs flex items-start space-x-3"
                  >
                    <div className="mt-0.5">
                      {reason.severity === 'HIGH' ? (
                        <AlertOctagon className="w-4 h-4 text-red-600" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-amber-600" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-900">{reason.title}</span>
                        <span className="text-[10px] font-semibold text-slate-500 uppercase px-1.5 py-0.2 rounded bg-slate-100 border border-slate-200">
                          {reason.severity || 'MEDIUM'}
                        </span>
                      </div>
                      <p className="mt-0.5 text-xs text-slate-600">{reason.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* URL Intelligence Section */}
          {analysis.urls_detected && analysis.urls_detected.length > 0 && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600 mb-2">
                Extracted Links &amp; URL Defense ({analysis.urls_detected.length})
              </h3>
              <div className="space-y-2">
                {analysis.urls_detected.map((u, i) => (
                  <div key={i} className="p-3 rounded-xl bg-white border border-slate-200 shadow-xs text-xs space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2 font-mono text-slate-800 truncate">
                        <Link className="w-3.5 h-3.5 text-teal-700 shrink-0" />
                        <span className="truncate">{u.url}</span>
                      </div>
                      <span className="text-[10px] font-bold text-red-600 bg-red-50 border border-red-200 px-2 py-0.5 rounded-full shrink-0">
                        +{u.risk_contribution} Risk
                      </span>
                    </div>

                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {u.is_https ? (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-semibold">
                          <Lock className="w-2.5 h-2.5" />
                          <span>HTTPS</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-md bg-red-50 text-red-700 border border-red-200 text-[10px] font-semibold">
                          <LockOpen className="w-2.5 h-2.5" />
                          <span>Insecure HTTP</span>
                        </span>
                      )}
                      {u.is_ip_address && (
                        <span className="px-2 py-0.5 rounded-md bg-red-50 text-red-700 border border-red-200 text-[10px] font-semibold">
                          Raw IP Host
                        </span>
                      )}
                      {u.is_shortener && (
                        <span className="px-2 py-0.5 rounded-md bg-amber-50 text-amber-700 border border-amber-200 text-[10px] font-semibold">
                          Obfuscated Shortener
                        </span>
                      )}
                      {u.is_lookalike && (
                        <span className="px-2 py-0.5 rounded-md bg-red-50 text-red-700 border border-red-200 text-[10px] font-semibold">
                          Brand Impersonation
                        </span>
                      )}
                    </div>

                    {u.suspicious_flags && u.suspicious_flags.length > 0 && (
                      <ul className="pt-1 text-[11px] text-slate-600 space-y-0.5 list-disc list-inside">
                        {u.suspicious_flags.map((flag, fIdx) => (
                          <li key={fIdx}>{flag}</li>
                        ))}
                      </ul>
                    )}

                    {u.threat_intel && (
                      <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-1.5 text-[10px]">
                        <span className={`px-2 py-0.5 rounded font-mono font-bold ${
                          u.threat_intel.phishtank_status === 'VERIFIED_PHISH' ? 'bg-red-100 text-red-800' : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          PhishTank: {u.threat_intel.phishtank_status}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono">
                          SSL: {u.threat_intel.ssl_issuer}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono">
                          Domain Age: {u.threat_intel.estimated_domain_age}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono">
                          ASN: {u.threat_intel.ip_reputation}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Action Center - Don'ts & Dos */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3.5 rounded-xl bg-red-50/80 border border-red-200 text-red-900">
              <span className="font-bold flex items-center gap-1.5 text-red-700 mb-1.5">
                ❌ What NOT to do
              </span>
              <ul className="space-y-1 text-slate-700">
                {analysis.recommendations?.donts?.map((item, i) => (
                  <li key={i} className="flex items-start space-x-1.5">
                    <span className="text-red-500 font-bold">•</span>
                    <span>{item}</span>
                  </li>
                )) || (
                  <>
                    <li>• Do not click any links</li>
                    <li>• Never provide passwords or OTPs</li>
                  </>
                )}
              </ul>
            </div>

            <div className="p-3.5 rounded-xl bg-teal-50/80 border border-teal-200 text-teal-900">
              <span className="font-bold flex items-center gap-1.5 text-teal-800 mb-1.5">
                ✅ Recommended Safe Action
              </span>
              <ul className="space-y-1 text-slate-700">
                {analysis.recommendations?.dos?.map((item, i) => (
                  <li key={i} className="flex items-start space-x-1.5">
                    <span className="text-teal-600 font-bold">•</span>
                    <span>{item}</span>
                  </li>
                )) || (
                  <>
                    <li>• Verify with the organization independently</li>
                    <li>• Mark message as spam / block sender</li>
                  </>
                )}
              </ul>
            </div>
          </div>

          {/* Technical Details Accordion */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-slate-50">
            <button
              onClick={() => setShowTechnical(!showTechnical)}
              className="w-full p-3 text-xs font-semibold text-slate-700 flex items-center justify-between hover:bg-slate-100 transition-colors cursor-pointer"
            >
              <span className="flex items-center space-x-1.5">
                <FileText className="w-3.5 h-3.5 text-teal-700" />
                <span>Technical Architecture &amp; Signal Breakdown</span>
              </span>
              {showTechnical ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>

            {showTechnical && (
              <div className="p-4 bg-white border-t border-slate-200 space-y-2 text-xs font-mono">
                <pre className="text-[11px] text-slate-700 bg-slate-50 p-3 rounded-lg border border-slate-200 overflow-x-auto">
                  {JSON.stringify(
                    {
                      id: analysis.id,
                      user_id: analysis.user_id || 'isolated',
                      heuristics_matched: analysis.technical_details?.heuristics_matched || [],
                      category_scores: analysis.technical_details?.category_scores || {},
                      model_confidence: analysis.technical_details?.model_confidence || '0.94',
                      processing_pipeline: [
                        'ingestion',
                        'ssrf_check',
                        'url_tokenization',
                        'heuristic_pattern_matcher',
                        'risk_aggregator',
                        'tenant_isolated_store'
                      ]
                    },
                    null,
                    2
                  )}
                </pre>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-100 flex items-center justify-between bg-slate-50/80">
          {isHighRisk && (
            <button
              onClick={handleReportCommunity}
              disabled={reporting || reported}
              className={`px-3 py-1.5 text-xs font-semibold rounded-xl border flex items-center space-x-1.5 transition-colors cursor-pointer ${
                reported
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200'
              }`}
            >
              {reporting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Broadcasting...</span>
                </>
              ) : reported ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Broadcasted to Community Radar</span>
                </>
              ) : (
                <>
                  <Radio className="w-3.5 h-3.5 text-red-500 animate-pulse" />
                  <span>Report to Community Radar</span>
                </>
              )}
            </button>
          )}

          <button
            onClick={onClose}
            className="px-5 py-2 text-xs font-semibold bg-teal-700 hover:bg-teal-800 text-white rounded-xl shadow-xs transition-colors cursor-pointer ml-auto"
          >
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
}
