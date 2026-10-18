import React, { useState, useEffect, useCallback, useRef } from 'react';
import Navbar from './components/Navbar';
import BottomNav from './components/BottomNav';
import AlertModal from './components/AlertModal';
import AnalysisModal from './components/AnalysisModal';
import MobileHeadsUpNotification from './components/MobileHeadsUpNotification';
import AuthModal from './components/AuthModal';
import DashboardView from './views/DashboardView';
import AlertsView from './views/AlertsView';
import HistoryView from './views/HistoryView';
import SourcesView from './views/SourcesView';
import SafetyView from './views/SafetyView';
import SettingsView from './views/SettingsView';
import { api, createWebSocketClient, playAlertChime, getAuthToken } from './services/api';

export default function App() {
  const [currentTab, setCurrentTab] = useState('home');
  const [currentUser, setCurrentUser] = useState(null);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('scamshield_theme') || 'light');

  const [dateRange, setDateRange] = useState('all');
  const [agentStatus, setAgentStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [history, setHistory] = useState([]);
  const [sources, setSources] = useState([]);
  const [settings, setSettings] = useState({
    protection_enabled: true,
    appearance: 'light',
    auto_alert_high: true,
    auto_alert_suspicious: true,
    high_risk_threshold: 70,
    suspicious_threshold: 30,
    privacy_minimal_metadata: true,
    sound_alerts: true,
  });

  const [soundEnabled, setSoundEnabled] = useState(true);
  const soundEnabledRef = useRef(soundEnabled);
  useEffect(() => {
    soundEnabledRef.current = soundEnabled;
  }, [soundEnabled]);

  const [wsConnected, setWsConnected] = useState(false);
  const [loadingToggle, setLoadingToggle] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isSendingCustom, setIsSendingCustom] = useState(false);

  // Modals & Notifications
  const [activeIncomingAlert, setActiveIncomingAlert] = useState(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [mobileHeadsUpNotification, setMobileHeadsUpNotification] = useState(null);

  // Search & Filter in History
  const [searchTerm, setSearchTerm] = useState('');
  const [activeRiskFilter, setActiveRiskFilter] = useState('ALL');

  // Apply Theme
  const applyTheme = useCallback((newTheme) => {
    setTheme(newTheme);
    localStorage.setItem('scamshield_theme', newTheme);
    if (newTheme === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else if (newTheme === 'light') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      // System
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (prefersDark) {
        document.documentElement.setAttribute('data-theme', 'dark');
      } else {
        document.documentElement.removeAttribute('data-theme');
      }
    }
  }, []);

  useEffect(() => {
    applyTheme(theme);
  }, [theme, applyTheme]);

  // Initial Auth Check & Auto Login if needed
  useEffect(() => {
    let isMounted = true;
    async function checkAuth() {
      try {
        if (!getAuthToken()) {
          const res = await api.login('user@scamshield.local', 'UserSafe2026!');
          if (isMounted && res?.user) {
            setCurrentUser(res.user);
            return;
          }
        }
        const user = await api.getCurrentUser();
        if (isMounted) setCurrentUser(user);
      } catch {
        try {
          const res = await api.login('user@scamshield.local', 'UserSafe2026!');
          if (isMounted) setCurrentUser(res?.user || null);
        } catch {
          if (isMounted) setCurrentUser(null);
        }
      }
    }
    checkAuth();
    return () => { isMounted = false; };
  }, []);

  // Fetch initial user data strictly ONCE when currentUser becomes available
  useEffect(() => {
    if (!currentUser?.id) return;
    let isMounted = true;

    async function loadInitialData() {
      try {
        const [statusData, alertsData, historyData, sourcesData, settingsData] = await Promise.all([
          api.getAgentStatus('all').catch(() => null),
          api.getAlerts().catch(() => []),
          api.getHistory('ALL', '', 50).catch(() => []),
          api.getSources().catch(() => []),
          api.getSettings().catch(() => null),
        ]);

        if (!isMounted) return;

        if (statusData) setAgentStatus(statusData);
        setAlerts(alertsData || []);
        setHistory(historyData || []);
        setSources(sourcesData || []);
        if (settingsData) {
          setSettings(settingsData);
          setSoundEnabled(settingsData.sound_alerts);
          if (settingsData.appearance && settingsData.appearance !== theme) {
            applyTheme(settingsData.appearance);
          }
        }
      } catch (err) {
        console.error('Error loading initial ScamShield data:', err);
      }
    }

    loadInitialData();
    return () => { isMounted = false; };
  }, [currentUser?.id]);

  // Authenticated WebSocket Live Listener (strictly tied to currentUser.id)
  useEffect(() => {
    if (!currentUser?.id) return;

    const wsClient = createWebSocketClient(
      (message) => {
        if (message.event === 'INITIAL_SYNC') {
          if (message.data?.stats) {
            setAgentStatus((prev) => ({
              ...(prev || {}),
              ...message.data.stats,
            }));
          }
        } else if (message.event === 'MESSAGE_PROCESSED') {
          const { analysis, stats, notification_tier } = message.data;

          if (stats) {
            setAgentStatus((prev) => ({
              ...(prev || {}),
              ...stats,
            }));
          }

          if (analysis) {
            setHistory((prev) => {
              if (prev.some((item) => item.id === analysis.id)) return prev;
              return [analysis, ...prev];
            });

            const newAlertItem = {
              id: `alt-${analysis.id}`,
              analysis_id: analysis.id,
              risk_level: analysis.risk_level,
              risk_score: analysis.risk_score,
              category: analysis.category,
              sender: analysis.sender,
              summary: analysis.summary,
              timestamp: analysis.timestamp,
              is_read: false,
              reasons_summary: (analysis.reasons || []).map((r) => r.title || r),
            };

            setMobileHeadsUpNotification(analysis);

            if (notification_tier === 'PROMINENT_ALERT' || analysis.risk_level === 'HIGH') {
              if (soundEnabledRef.current) playAlertChime(true);
              setActiveIncomingAlert(analysis);
              setAlerts((prev) => {
                if (prev.some((a) => a.analysis_id === analysis.id || a.id === `alt-${analysis.id}`)) return prev;
                return [newAlertItem, ...prev];
              });
            } else if (notification_tier === 'SUBTLE_NOTICE' || analysis.risk_level === 'SUSPICIOUS') {
              if (soundEnabledRef.current) playAlertChime(false);
              setAlerts((prev) => {
                if (prev.some((a) => a.analysis_id === analysis.id || a.id === `alt-${analysis.id}`)) return prev;
                return [newAlertItem, ...prev];
              });
            }
          }
        } else if (message.event === 'DATA_WIPED') {
          setHistory([]);
          setAlerts([]);
          if (message.data?.stats) {
            setAgentStatus((prev) => ({
              ...(prev || {}),
              ...message.data.stats,
            }));
          }
        }
      },
      (connected) => setWsConnected(connected)
    );

    return () => {
      wsClient.disconnect();
    };
  }, [currentUser?.id]);

  // Handlers
  const handleToggleProtection = async () => {
    setLoadingToggle(true);
    try {
      const isActive = agentStatus?.protection_active;
      const res = isActive ? await api.pauseProtection() : await api.startProtection();
      setAgentStatus((prev) => ({
        ...(prev || {}),
        protection_active: res.protection_active,
        status_label: res.status_label,
      }));
    } catch (err) {
      console.error('Failed to toggle protection:', err);
    } finally {
      setLoadingToggle(false);
    }
  };

  const handleNewAnalysis = useCallback((res) => {
    if (!res) return;
    setHistory((prev) => [res, ...prev.filter((i) => i.id !== res.id)]);

    // 1. Instantly update metrics locally for zero-lag visual feedback
    setAgentStatus((prev) => {
      if (!prev) return prev;
      const isThreat = res.risk_level === 'HIGH' || res.risk_level === 'SUSPICIOUS';
      return {
        ...prev,
        messages_checked: (prev.messages_checked || 0) + 1,
        threats_detected: (prev.threats_detected || 0) + (isThreat ? 1 : 0),
        high_risk_count: (prev.high_risk_count || 0) + (res.risk_level === 'HIGH' ? 1 : 0),
        suspicious_count: (prev.suspicious_count || 0) + (res.risk_level === 'SUSPICIOUS' ? 1 : 0),
        last_active: 'Just now',
      };
    });

    // 2. Instantly trigger alert modal & notification if high or suspicious threat
    const newAlert = {
      id: `alt-${res.id}`,
      analysis_id: res.id,
      risk_level: res.risk_level,
      risk_score: res.risk_score,
      category: res.category,
      sender: res.sender,
      summary: res.summary,
      timestamp: res.timestamp,
      is_read: false,
      reasons_summary: (res.reasons || []).map((r) => r.title || r),
    };

    // Mobile Haptic Vibration Alert
    if ('vibrate' in navigator) {
      try {
        if (res.risk_level === 'HIGH') {
          navigator.vibrate([250, 100, 250]);
        } else if (res.risk_level === 'SUSPICIOUS') {
          navigator.vibrate([150]);
        }
      } catch {}
    }

    // Native Mobile & Browser Notification
    if ('Notification' in window && Notification.permission === 'granted' && (res.risk_level === 'HIGH' || res.risk_level === 'SUSPICIOUS')) {
      try {
        new Notification(`🛡️ ScamShield Alert: ${res.risk_level} RISK`, {
          body: `${res.sender}: ${res.summary}`,
          icon: '/favicon.svg',
          badge: '/favicon.svg',
          tag: `scamshield-${res.id}`,
        });
      } catch {}
    }

    // Trigger Mobile Heads-Up Drop Notification
    setMobileHeadsUpNotification(res);

    if (res.risk_level === 'HIGH') {
      if (soundEnabledRef.current) playAlertChime(true);
      setActiveIncomingAlert(res);
      setAlerts((prev) => [
        newAlert,
        ...prev.filter((a) => a.analysis_id !== res.id && a.id !== `alt-${res.id}`),
      ]);
    } else if (res.risk_level === 'SUSPICIOUS') {
      if (soundEnabledRef.current) playAlertChime(false);
      setAlerts((prev) => [
        newAlert,
        ...prev.filter((a) => a.analysis_id !== res.id && a.id !== `alt-${res.id}`),
      ]);
    }
  }, []);

  const handleTriggerScenario = async (type) => {
    setIsSimulating(true);
    try {
      const res = await api.simulateScenario(type);
      handleNewAnalysis(res);
    } catch (err) {
      console.error('Failed to simulate scenario:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleSendCustomMessage = async (msgData) => {
    setIsSendingCustom(true);
    try {
      const res = await api.sendIncomingMessage(msgData);
      handleNewAnalysis(res);
      setSelectedAnalysis(res);
    } catch (err) {
      console.error('Failed to send custom message:', err);
    } finally {
      setIsSendingCustom(false);
    }
  };

  // Mobile Web Share Target & URL Ingestion Listener
  useEffect(() => {
    try {
      const searchParams = new URLSearchParams(window.location.search);
      const sharedText = searchParams.get('text') || searchParams.get('url') || searchParams.get('title');
      if (sharedText && sharedText.trim()) {
        handleSendCustomMessage({
          source: 'MOBILE_SHARE',
          sender: 'Shared from Mobile App',
          content: sharedText.trim(),
        });
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    } catch {}
  }, []);

  const handleDateRangeChange = (newRange) => {
    setDateRange(newRange);
    api.getAgentStatus(newRange).then((s) => {
      if (s) setAgentStatus(s);
    }).catch(() => {});
  };

  const handleMarkRead = async (alertId) => {
    try {
      await api.markAlertRead(alertId);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, is_read: true } : a))
      );
    } catch (err) {
      console.error('Failed to mark alert as read:', err);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await api.markAllAlertsRead();
      setAlerts((prev) => prev.map((a) => ({ ...a, is_read: true })));
    } catch (err) {
      console.error('Failed to mark all alerts read:', err);
    }
  };

  const handleDeleteHistoryEntry = async (analysisId) => {
    try {
      await api.deleteHistoryEntry(analysisId);
      setHistory((prev) => prev.filter((item) => item.id !== analysisId));
    } catch (err) {
      console.error('Failed to delete history entry:', err);
    }
  };

  const handleClearHistory = async () => {
    try {
      await api.clearMyHistory();
      setHistory([]);
      const stats = await api.getAgentStatus(dateRange);
      setAgentStatus(stats);
    } catch (err) {
      console.error('Failed to clear history:', err);
    }
  };

  const handleSaveSettings = async (newSettings) => {
    try {
      const saved = await api.updateSettings(newSettings);
      setSettings(saved);
      setSoundEnabled(saved.sound_alerts);
      if (saved.appearance) {
        applyTheme(saved.appearance);
      }
    } catch (err) {
      console.error('Failed to save settings:', err);
      throw err;
    }
  };

  const handleLogout = async () => {
    await api.logout();
    setCurrentUser(null);
    setHistory([]);
    setAlerts([]);
    setAuthModalOpen(true);
  };

  const unreadAlertsCount = alerts.filter((a) => !a.is_read).length;

  return (
    <div className="min-h-screen flex flex-col bg-[#F5F7FB] text-[#172033] transition-colors">
      {/* Top Navigation Bar */}
      <Navbar
        agentStatus={agentStatus}
        wsConnected={wsConnected}
        unreadCount={unreadAlertsCount}
        soundEnabled={soundEnabled}
        setSoundEnabled={setSoundEnabled}
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        onOpenAlerts={() => setCurrentTab('alerts')}
        currentUser={currentUser}
        onOpenAuth={() => setAuthModalOpen(true)}
        onLogout={handleLogout}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 lg:px-8 py-6 pb-24 md:pb-8">
        {currentTab === 'home' && (
          <DashboardView
            agentStatus={agentStatus}
            onToggleProtection={handleToggleProtection}
            loadingToggle={loadingToggle}
            onTriggerScenario={handleTriggerScenario}
            isSimulating={isSimulating}
            recentAnalyses={history}
            onViewAnalysis={(analysis) => setSelectedAnalysis(analysis)}
            onNavigateHistory={() => setCurrentTab('history')}
            onMessageAnalyzed={handleNewAnalysis}
            dateRange={dateRange}
            onDateRangeChange={handleDateRangeChange}
          />
        )}

        {currentTab === 'alerts' && (
          <AlertsView
            alerts={alerts}
            onMarkRead={handleMarkRead}
            onMarkAllRead={handleMarkAllRead}
            onViewAnalysis={(alert) => {
              const full = history.find((h) => h.id === alert.analysis_id || h.id === alert.id);
              setSelectedAnalysis(full || alert);
            }}
          />
        )}

        {currentTab === 'history' && (
          <HistoryView
            history={history}
            onFilterRisk={(r) => setActiveRiskFilter(r)}
            activeRiskFilter={activeRiskFilter}
            searchTerm={searchTerm}
            setSearchTerm={setSearchTerm}
            onDeleteEntry={handleDeleteHistoryEntry}
            onClearHistory={handleClearHistory}
            onViewAnalysis={(analysis) => setSelectedAnalysis(analysis)}
          />
        )}

        {currentTab === 'sources' && (
          <SourcesView
            sources={sources}
            onConnectSource={async (id) => {
              await api.toggleSource(id, true);
              const s = await api.getSources();
              setSources(s);
            }}
            onDisconnectSource={async (id) => {
              await api.toggleSource(id, false);
              const s = await api.getSources();
              setSources(s);
            }}
            onSendCustomMessage={handleSendCustomMessage}
            isSendingCustom={isSendingCustom}
            onMessageAnalyzed={handleNewAnalysis}
            onViewAnalysis={(analysis) => setSelectedAnalysis(analysis)}
            onTriggerScenario={handleTriggerScenario}
          />
        )}

        {currentTab === 'safety' && <SafetyView />}

        {currentTab === 'settings' && (
          <SettingsView
            settings={settings}
            onSaveSettings={handleSaveSettings}
            onClearHistory={handleClearHistory}
            currentUser={currentUser}
            onThemeChange={(newTheme) => applyTheme(newTheme)}
          />
        )}
      </main>

      {/* Mobile Bottom Navigation */}
      <BottomNav
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        unreadCount={unreadAlertsCount}
      />

      {/* Mobile Heads-Up Floating Alert Notification */}
      <MobileHeadsUpNotification
        notification={mobileHeadsUpNotification}
        onClose={() => setMobileHeadsUpNotification(null)}
        onInspect={(analysis) => {
          setSelectedAnalysis(analysis);
          setActiveIncomingAlert(null);
        }}
      />

      {/* Pop-up Modals */}
      <AlertModal
        alert={activeIncomingAlert}
        onClose={() => setActiveIncomingAlert(null)}
        onViewDetails={(alert) => {
          setActiveIncomingAlert(null);
          setSelectedAnalysis(alert);
        }}
      />

      <AnalysisModal
        analysis={selectedAnalysis}
        onClose={() => setSelectedAnalysis(null)}
      />

      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onAuthSuccess={(user) => {
          setCurrentUser(user);
        }}
      />
    </div>
  );
}
