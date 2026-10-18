import React, { useState, useEffect } from 'react';
import {
  Network,
  Share2,
  Database,
  AlertTriangle,
  Info,
  Layers,
  Sparkles,
  RefreshCw,
  Terminal,
  ShieldAlert,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { api } from '../services/api';

export default function GraphInvestigationCard({ messageId, messageContent, initialAnalysis }) {
  const [investigation, setInvestigation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [showRawGraph, setShowRawGraph] = useState(false);

  const fetchInvestigation = async () => {
    setLoading(true);
    setError(null);
    try {
      let data;
      if (messageId) {
        data = await api.getInvestigation(messageId);
      } else {
        data = await api.investigateMessage({
          content: messageContent,
          sender: initialAnalysis?.sender || 'Inbound Message'
        });
      }
      setInvestigation(data);
    } catch (err) {
      console.error('Graph investigation error:', err);
      setError(err.message || 'Unable to complete graph investigation.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInvestigation();
  }, [messageId]);

  if (loading) {
    return (
      <div className="p-6 rounded-2xl bg-slate-900 text-white border border-slate-800 shadow-xl space-y-4 animate-pulse">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-teal-500/20 text-teal-400">
            <Network className="w-5 h-5 animate-spin" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
              TRAVERSING FALKORDB KNOWLEDGE GRAPH...
            </h3>
            <p className="text-xs text-slate-400">
              Querying Cypher relationships, shared indicators, and threat intelligence paths...
            </p>
          </div>
        </div>
        <div className="h-32 bg-slate-800/60 rounded-xl flex items-center justify-center">
          <span className="text-xs text-slate-400 flex items-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-teal-400" />
            Matching adversarial clusters in graph...
          </span>
        </div>
      </div>
    );
  }

  if (error) {
    const isOffline = error.toLowerCase().includes('unavailable') || error.toLowerCase().includes('connection') || error.toLowerCase().includes('failed');
    return (
      <div className="p-5 rounded-2xl bg-amber-950/20 border border-amber-800/40 text-amber-200 space-y-3">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs">
            <h4 className="font-bold text-amber-300">FalkorDB Graph Investigation Notice</h4>
            <p className="text-amber-200/90 leading-relaxed">{error}</p>
            {isOffline && (
              <div className="mt-2 p-2.5 rounded-lg bg-slate-950/80 border border-amber-900/50 font-mono text-[11px] text-slate-300">
                <p className="text-teal-400 font-bold mb-1">💡 Quick FalkorDB Local Launch Command:</p>
                <code>docker run -p 6379:6379 -d falkordb/falkordb:latest</code>
              </div>
            )}
            <button
              onClick={fetchInvestigation}
              className="mt-2 px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Retry Investigation
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!investigation) return null;

  const {
    graph_summary,
    shared_indicators = [],
    threat_reports = [],
    agent_explanation,
    limitations_and_uncertainty,
    visual_network = { nodes: [], edges: [] }
  } = investigation;

  const isCampaign = graph_summary?.is_active_campaign;
  const nodes = visual_network.nodes || [];
  const edges = visual_network.edges || [];

  return (
    <div className="rounded-2xl bg-slate-950 border border-slate-800 text-slate-200 overflow-hidden shadow-2xl space-y-4">
      {/* Top Banner */}
      <div className="p-4 border-b border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-teal-950/40 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-teal-500/10 border border-teal-500/30 text-teal-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold uppercase tracking-wider text-teal-400 flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5" /> FalkorDB Graph Investigation
              </span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                isCampaign
                  ? 'bg-red-500/10 text-red-400 border-red-500/30'
                  : 'bg-teal-500/10 text-teal-300 border-teal-500/30'
              }`}>
                {isCampaign ? '⚠️ CONNECTED ADVERSARIAL CLUSTER' : '🟢 NO SHARED THREATS'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Knowledge Graph: <strong className="text-slate-200">scamshield</strong> • {nodes.length} Connected Nodes • {edges.length} Relationships
            </p>
          </div>
        </div>

        <button
          onClick={fetchInvestigation}
          className="text-xs text-slate-400 hover:text-white flex items-center gap-1 px-2.5 py-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
        >
          <RefreshCw className="w-3 h-3" /> Refresh Graph
        </button>
      </div>

      <div className="p-4 space-y-4">
        {/* Agent Explanation Grounded in Graph Findings */}
        <div className="p-3.5 rounded-xl bg-teal-950/20 border border-teal-800/40 text-xs space-y-2">
          <div className="flex items-center space-x-2 text-teal-300 font-bold">
            <Sparkles className="w-4 h-4 text-teal-400" />
            <span>Agent Graph-Grounded Investigation Summary</span>
          </div>
          <div className="text-slate-300 leading-relaxed whitespace-pre-line text-[11.5px]">
            {agent_explanation}
          </div>
        </div>

        {/* Visual Graph Representation Canvas */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-4 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-300 flex items-center gap-1.5">
              <Share2 className="w-3.5 h-3.5 text-teal-400" />
              Connected Entity &amp; Indicator Graph
            </span>
            <div className="flex items-center space-x-2 text-[10px] text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-blue-500 inline-block" /> Message
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-amber-500 inline-block" /> Domain
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" /> Org
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> Report
              </span>
            </div>
          </div>

          {/* Node Grid Layout */}
          {nodes.length > 0 ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5 pt-1">
              {nodes.map((n) => {
                const isSelected = selectedNode?.id === n.id;
                let badgeColor = 'bg-slate-800 text-slate-300 border-slate-700';
                if (n.type === 'Message') badgeColor = 'bg-blue-950/60 text-blue-300 border-blue-700/50';
                else if (n.type === 'Domain') badgeColor = 'bg-amber-950/60 text-amber-300 border-amber-700/50';
                else if (n.type === 'Organization') badgeColor = 'bg-emerald-950/60 text-emerald-300 border-emerald-700/50';
                else if (n.type === 'Report') badgeColor = 'bg-red-950/60 text-red-300 border-red-700/50';
                else if (n.type === 'Phone') badgeColor = 'bg-purple-950/60 text-purple-300 border-purple-700/50';
                else if (n.type === 'Indicator') badgeColor = 'bg-pink-950/60 text-pink-300 border-pink-700/50';

                return (
                  <button
                    key={n.id}
                    onClick={() => setSelectedNode(isSelected ? null : n)}
                    className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${badgeColor} ${
                      isSelected ? 'ring-2 ring-teal-400 scale-[1.02]' : 'hover:border-slate-500'
                    }`}
                  >
                    <div className="text-[10px] uppercase font-bold tracking-wider opacity-70 mb-0.5">
                      {n.type}
                    </div>
                    <div className="text-xs font-semibold truncate" title={n.label || n.id}>
                      {n.label || n.id}
                    </div>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-slate-500 italic">
              No direct external graph nodes connected yet.
            </div>
          )}

          {/* Active Node Detail Inspector */}
          {selectedNode && (
            <div className="p-3 rounded-lg bg-slate-950/90 border border-teal-500/30 text-xs space-y-1 animate-in fade-in">
              <div className="flex items-center justify-between">
                <span className="font-bold text-teal-300 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5" /> Node Inspector: {selectedNode.type}
                </span>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white text-[11px]"
                >
                  ✕
                </button>
              </div>
              <p className="text-slate-300 font-mono text-[11px] break-all">
                Identifier: {selectedNode.id}
              </p>
              <div className="text-[10px] text-slate-400">
                Connected Relationships: {edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).length} edges
              </div>
            </div>
          )}
        </div>

        {/* Shared Indicators Section */}
        {shared_indicators.length > 0 && (
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-amber-400" />
                Shared Indicators Across Historical Messages ({shared_indicators.length})
              </span>
              <span className="text-[10px] text-amber-400 font-semibold bg-amber-400/10 px-2 py-0.5 rounded-full border border-amber-400/30">
                Cross-Message Infrastructure
              </span>
            </div>

            <div className="space-y-2">
              {shared_indicators.map((item, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs flex items-start justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-amber-300 font-mono text-[11px]">
                        {item.indicator_value}
                      </span>
                      <span className="text-[10px] text-slate-400 px-1.5 py-0.2 rounded bg-slate-800">
                        {item.indicator_type} ({item.relationship})
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px] italic line-clamp-1">
                      "{item.related_message?.preview}"
                    </p>
                  </div>

                  <div className="text-right shrink-0">
                    <span className="text-[10px] font-bold text-red-400">
                      Risk: {item.related_message?.risk_score}/100
                    </span>
                    <div className="text-[10px] text-slate-500">
                      {item.related_message?.timestamp || 'Historic'}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Threat Intelligence Reports Section */}
        {threat_reports.length > 0 && (
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                Linked Threat Intelligence &amp; Benchmark Reports ({threat_reports.length})
              </span>
            </div>

            <div className="space-y-2">
              {threat_reports.map((r, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-red-950/10 border border-red-900/30 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between flex-wrap gap-1">
                    <span className="font-bold text-red-300 text-xs">{r.title}</span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-300 border border-red-500/40">
                      {r.verification_status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed">{r.summary}</p>
                  <div className="text-[10px] text-slate-500 pt-1 flex items-center justify-between">
                    <span>Source: {r.source}</span>
                    <span>{r.date || 'Active intelligence'}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Critical Limitation & Uncertainty Statement */}
        <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 flex items-start space-x-2">
          <Info className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="text-slate-300">Methodological Disclosure:</strong> {limitations_and_uncertainty}
          </p>
        </div>

        {/* Raw Cypher / JSON Inspector Accordion */}
        <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900">
          <button
            onClick={() => setShowRawGraph(!showRawGraph)}
            className="w-full p-2.5 text-xs font-semibold text-slate-400 hover:text-white flex items-center justify-between transition-colors cursor-pointer"
          >
            <span className="flex items-center space-x-1.5">
              <Terminal className="w-3.5 h-3.5 text-teal-400" />
              <span>Inspect Raw Graph Investigation JSON Payload</span>
            </span>
            {showRawGraph ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          {showRawGraph && (
            <div className="p-3 bg-slate-950 border-t border-slate-800 text-[11px] font-mono overflow-x-auto max-h-60">
              <pre className="text-teal-300">
                {JSON.stringify(investigation, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
