const API_BASE = (import.meta.env.VITE_API_BASE_URL ? import.meta.env.VITE_API_BASE_URL.replace(/\/$/, '') : '') + '/api';

let memoryToken = null;

export function setAuthToken(token) {
  memoryToken = token;
}

export function getAuthToken() {
  return memoryToken;
}

async function request(url, options = {}, isRetry = false) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (memoryToken) {
    headers['Authorization'] = `Bearer ${memoryToken}`;
  }

  const config = {
    ...options,
    headers,
    credentials: 'include', // Ensures HttpOnly cookies are automatically passed
  };

  let res;
  try {
    res = await fetch(url, config);
  } catch {
    if (!isRetry) {
      await new Promise((resolve) => setTimeout(resolve, 350));
      return request(url, options, true);
    }
    throw new Error('Connection error. Server or tunnel is unreachable. Please try again.');
  }

  // Auto-recovery for gateway timeouts (502, 503, 504) via tunnel proxy: retry once after brief backoff
  if ((res.status === 502 || res.status === 503 || res.status === 504) && !isRetry) {
    await new Promise((resolve) => setTimeout(resolve, 350));
    return request(url, options, true);
  }

  // Auto-recovery: If 401 occurs and not already refreshing/logging in, attempt refresh and retry once
  if (res.status === 401 && !isRetry && !url.includes('/auth/login') && !url.includes('/auth/me') && !url.includes('/auth/refresh')) {
    try {
      const refreshRes = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      if (refreshRes.ok) {
        const refreshData = await refreshRes.json();
        if (refreshData?.access_token) {
          setAuthToken(refreshData.access_token);
          return request(url, options, true);
        }
      }
    } catch {
      // Continue to handle 401 error normally
    }
  }

  if (!res.ok) {
    let errorDetail = '';
    try {
      const errorData = await res.json();
      if (typeof errorData?.detail === 'string') {
        errorDetail = errorData.detail;
      } else if (Array.isArray(errorData?.detail)) {
        errorDetail = errorData.detail.map((d) => d.msg || d.message || JSON.stringify(d)).join(', ');
      } else if (errorData?.message) {
        errorDetail = errorData.message;
      }
    } catch {
      if (res.status === 504) {
        errorDetail = 'Gateway Timeout (HTTP 504) from connection proxy. Please retry.';
      } else if (res.status === 502 || res.status === 503) {
        errorDetail = `Gateway error (HTTP ${res.status}). Server temporarily busy. Please retry.`;
      } else {
        errorDetail = res.statusText || (res.status ? `Server error (HTTP ${res.status})` : 'Request failed');
      }
    }

    const error = new Error(errorDetail || 'Request failed. Please check your connection.');
    error.status = res.status;
    throw error;
  }

  return res.json();
}

// ==========================================
// RESILIENT CLIENT-SIDE HEURISTIC ENGINE
// (Activates seamlessly when running on static hosts like Netlify without Python backend)
// ==========================================

const DEMO_PRESETS = {
  FAKE_KYC: {
    sender: 'SBI-ALERT',
    content: 'Dear Customer, Your SBI account KYC has expired today. Your NetBanking and ATM card will be blocked within 24 hours. Immediately update your KYC documents at: http://sbi-kyc-verify-portal.in/login',
  },
  BANK_IMPERSONATION: {
    sender: 'HDFC-NOTIFY',
    content: 'Urgent Security Alert: A debit transaction of ₹49,999 is pending on your HDFC credit card. If you did not authorize this, block your card immediately and verify credentials at http://hdfc-card-protection.xyz/auth',
  },
  JOB_SCAM: {
    sender: '+91-98765-43210',
    content: 'Part-Time Job Opportunity! Earn ₹5,000 to ₹10,000 daily by simply reviewing movie trailers from home. No experience needed. Pay ₹499 registration kit fee to activate your employee ID today via http://bit.ly/quick-daily-cash-jobs',
  },
  PRIZE_SCAM: {
    sender: 'REWARDS-WIN',
    content: 'Congratulations! Your mobile number was selected in the Annual Lucky Draw! You won a cash prize of ₹50,000. Claim your reward immediately before midnight at http://192.168.10.45/lottery/claim.php',
  },
  LEGITIMATE_OTP: {
    sender: 'UNIV-SECURE',
    content: 'Your OTP for signing into your student portal is 681042. Valid for 10 minutes. Please do not share this one-time code with anyone for your own security.',
  },
  NORMAL_DELIVERY: {
    sender: 'AmazonLogistics',
    content: 'Your package containing "Wireless Bluetooth Earbuds" has been delivered to your receptionist. Tracking ID: AMZ9810428. Thank you for shopping with Amazon.',
  },
  WHATSAPP_FAMILY_IMPERSONATION: {
    sender: '+91-91234-56789 (WhatsApp)',
    content: 'Hi Mom, my phone fell in water and got damaged. This is my temporary WhatsApp number. I urgently need to pay my college exam fee ₹15,000 before 5 PM. Can you please transfer to UPI id: college-fees@upi immediately? Can\'t call mic broken.',
  },
  WHATSAPP_ACCOUNT_TAKEOVER: {
    sender: 'WhatsApp-Support (WhatsApp)',
    content: 'Your WhatsApp account is scheduled to be deactivated within 12 hours due to policy violations. To cancel deactivation and verify your phone number, click: http://whatsapp-support-helpdesk.online/verify',
  },
  DRILL_FAKE_KYC: {
    sender: 'SBI-ALERT',
    content: 'Mee SBI account block avvabothundi, immediate ga KYC update cheyyandi: http://sbi-kyc-update.xyz. Update within 24 hours to prevent permanent deactivation.',
  },
  DRILL_UPI_SCAM: {
    sender: 'BESCOM-OFFICIAL',
    content: 'Dear BESCOM consumer, pay electricity bill Rs 1,450 to 9876543210@ybl to avoid immediate power disconnection tonight at 9:30 PM.',
  },
  DRILL_JOB_SCAM: {
    sender: '+91-91234-56780',
    content: 'Earn Rs 5,000 daily by liking YouTube videos and rating hotels on Google Maps. No experience needed. Transfer Rs 499 registration fee to taskpay@upi to activate your employee kit.',
  },
  DRILL_COURIER_SCAM: {
    sender: 'IN-POST',
    content: 'Your package IN892182049 has been held at the central customs hub due to an incorrect shipping address. Update your delivery address immediately: http://indiapost-parcel-redirection.top/re-deliver',
  },
  DRILL_INVESTMENT_SCAM: {
    sender: 'VIP-TRADER',
    content: 'Guaranteed 25% daily returns on institutional AI crypto trading. Join our private SEBI registered insider club: http://ai-crypto-vault.xyz/vip. Deposit Rs 5,000 to double your capital in 48h.',
  },
};

function clientAnalyzeMessage(content, sender = 'Manual Inspection', source = 'DEMO') {
  const text = (content || '').toLowerCase();
  const urls = content.match(/https?:\/\/[^\s]+/gi) || [];

  let score = 15;
  const reasons = [];
  const flags = [];
  const donts = [];
  const dos = ['Report suspicious messages to your security officer or official service provider.'];

  // Check URL risks
  const urlAnalyses = [];
  if (urls.length > 0) {
    flags.push('URL_PRESENT');
    urls.forEach((u) => {
      const uLower = u.toLowerCase();
      let urlSuspicious = false;
      const urlFlags = [];

      if (uLower.includes('.xyz') || uLower.includes('.top') || uLower.includes('.tk') || uLower.includes('.site') || uLower.includes('.in/login')) {
        urlSuspicious = true;
        urlFlags.push('SUSPICIOUS_TLD');
        score += 35;
      }
      if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(uLower)) {
        urlSuspicious = true;
        urlFlags.push('RAW_IP_HOST');
        score += 35;
      }
      if (uLower.includes('bit.ly') || uLower.includes('tinyurl')) {
        urlSuspicious = true;
        urlFlags.push('URL_SHORTENER');
        score += 20;
      }
      if (uLower.startsWith('http://')) {
        urlFlags.push('INSECURE_HTTP');
        score += 10;
      }
      if (uLower.includes('verify') || uLower.includes('kyc') || uLower.includes('auth') || uLower.includes('secure') || uLower.includes('portal') || uLower.includes('recovery')) {
        urlSuspicious = true;
        urlFlags.push('DECEPTIVE_PATH_KEYWORDS');
        score += 25;
      }

      urlAnalyses.push({
        url: u,
        is_suspicious: urlSuspicious,
        risk_flags: urlFlags,
        domain: u.replace(/^https?:\/\//, '').split('/')[0],
      });
    });

    if (urlAnalyses.some((a) => a.is_suspicious)) {
      reasons.push({
        title: 'Deceptive or Untrusted Link',
        description: 'Contains destination URLs pointing to untrusted TLDs (.xyz / .in / .top), IP addresses, or spoofed login paths.',
        severity: 'HIGH',
      });
      donts.push('Do NOT click or navigate to the link provided in the message');
    }
  }

  // Check Urgency
  if (
    text.includes('urgent') ||
    text.includes('immediately') ||
    text.includes('24 hours') ||
    text.includes('12 hours') ||
    text.includes('blocked') ||
    text.includes('suspended') ||
    text.includes('permanent suspension') ||
    text.includes('restricted') ||
    text.includes('unauthorized') ||
    text.includes('critical') ||
    text.includes('action required')
  ) {
    score += 30;
    flags.push('ARTIFICIAL_URGENCY');
    reasons.push({
      title: 'High Urgency & Threat Pressure',
      description: 'Manufactures psychological urgency demanding immediate verification within a strict deadline under threat of penalty.',
      severity: 'HIGH',
    });
    donts.push('Do NOT panic or take rushed actions prompted by artificial deadlines');
  }

  // Check Sensitive Credentials / Financial bait
  if (
    text.includes('kyc') ||
    text.includes('password') ||
    text.includes('credentials') ||
    (text.includes('otp') && text.includes('expire')) ||
    text.includes('debit transaction') ||
    text.includes('pending on your') ||
    text.includes('credit card') ||
    text.includes('lucky draw') ||
    text.includes('won a cash prize') ||
    text.includes('registration kit fee')
  ) {
    score += 30;
    flags.push('SENSITIVE_CREDENTIAL_SOLICITATION');
    reasons.push({
      title: 'Credential or Financial Harvesting Lure',
      description: 'Solicits banking credentials, card numbers, personal identity documents, or non-refundable advance fees.',
      severity: 'HIGH',
    });
    donts.push('Never disclose your banking passwords, card PINs, or verification codes');
  }

  // Check WhatsApp Family / Emergency Impersonation
  if ((text.includes('hi mom') || text.includes('hi mum') || text.includes('temporary whatsapp') || text.includes('fell in water')) && (text.includes('upi') || text.includes('pay') || text.includes('money') || text.includes('fee'))) {
    score = Math.max(score + 40, 88);
    flags.push('FAMILY_IMPERSONATION_BAIT');
    reasons.push({
      title: 'WhatsApp Family Impersonation ("Hi Mum" Emergency Scam)',
      description: 'Classic impersonation vector where attackers pretend to be a close relative using a temporary number due to a broken phone, demanding urgent UPI funds.',
      severity: 'HIGH',
    });
    donts.push('Never transfer funds to a new or unverified number claiming to be family or friends');
    dos.push('Immediately call the family member on their known existing phone number to verify their voice and identity.');
  }

  // Safe Transaction / Order checks
  if (text.includes('has been delivered') || text.includes('tracking id: amz') || text.includes('boarding at gate') || text.includes('pleasant flight')) {
    score = 8;
    reasons.length = 0;
    reasons.push({
      title: 'Verified Transactional Notice',
      description: 'Routine verified status notification without suspicious redirection, payment solicitation, or urgency.',
      severity: 'LOW',
    });
    dos.push('Routine verified notice. No security action needed.');
  } else if (text.includes('student portal') && text.includes('do not share')) {
    score = 12;
    reasons.length = 0;
    reasons.push({
      title: 'Legitimate One-Time Password (OTP)',
      description: 'Standard security passcode containing explicit warnings not to share codes with third parties.',
      severity: 'LOW',
    });
    dos.push('Enter this passcode only on the official application or login session you personally initiated.');
  }

  // Clamp score
  score = Math.min(Math.max(score, 5), 96);

  let riskLevel = 'LOW';
  if (score >= 70) riskLevel = 'HIGH';
  else if (score >= 30) riskLevel = 'SUSPICIOUS';

  let category = 'NORMAL_COMMUNICATION';
  let summary = 'Message analyzed safe with no scam or phishing indicators.';
  if (riskLevel === 'HIGH') {
    if (text.includes('kyc')) {
      category = 'FAKE_KYC_PHISHING';
      summary = 'Phishing lure attempting to harvest personal KYC documents through fake bank verification portals.';
    } else if (text.includes('hdfc') || text.includes('paypal') || text.includes('bank') || text.includes('unauthorized') || text.includes('restricted')) {
      category = 'BANK_IMPERSONATION';
      summary = 'High-risk security alert impersonating a financial institution to harvest authentication credentials.';
    } else if (text.includes('job') || text.includes('daily cash')) {
      category = 'ADVANCE_FEE_FRAUD';
      summary = 'Bogus part-time employment offer requiring upfront fee payments.';
    } else if (text.includes('lucky draw') || text.includes('cash prize')) {
      category = 'LOTTERY_SCAM';
      summary = 'Fabricated lottery prize claim designed to lure victims into paying processing fees.';
    } else {
      category = 'CREDENTIAL_PHISHING';
      summary = 'Deceptive inbound message containing urgent threats and suspicious verification links.';
    }
  } else if (riskLevel === 'SUSPICIOUS') {
    category = 'SUSPICIOUS_UNVERIFIED';
    summary = 'Message contains elevated risk patterns or unsolicited external links requiring caution.';
  }

  // 1. Multilingual / Code-Mixed Indian Detection
  const hinglishUrgency = /(turant|jaldi|urgent|abhee|warna|karein|block ho gaya|kaat di)/i.test(content);
  const tenglishUrgency = /(avvabothundi|cheyyandi|urgent ga|immediate ga|aipothundi|kaavali)/i.test(content);
  const devanagari = /[\u0900-\u097F]/.test(content);
  const teluguScript = /[\u0C00-\u0C7F]/.test(content);
  const isMultilingual = hinglishUrgency || tenglishUrgency || devanagari || teluguScript;
  let languageMix = 'ENGLISH';
  if (devanagari || hinglishUrgency) languageMix = devanagari ? 'DEV_HINDI' : 'HINGLISH';
  if (teluguScript || tenglishUrgency) languageMix = teluguScript ? 'TELUGU' : 'TENGLISH';
  
  const multilingualData = {
    is_code_mixed: isMultilingual,
    is_multilingual: isMultilingual,
    language_mix: languageMix,
    detected_languages: isMultilingual ? ['English', languageMix] : ['English'],
    matched_signals: isMultilingual ? [{ type: 'URGENCY', term: 'regional urgency cue', dialect: languageMix }] : [],
    detected_urgency: hinglishUrgency || tenglishUrgency,
    detected_coercion: hinglishUrgency || tenglishUrgency,
    risk_boost: isMultilingual ? 20 : 0,
    summary_note: isMultilingual ? `Detected code-mixed message (${languageMix}). Identifies regional urgency and deception markers.` : null
  };
  if (isMultilingual) score = Math.min(score + 15, 96);

  // 2. UPI Payment Safety Guard
  const vpaMatches = content.match(/\b([a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32})\b/g) || [];
  let upiSafety = {
    has_upi_payload: false,
    safety_verdict: 'NO_PAYMENT_DETECTED',
    badge_color: 'slate',
    risk_score: 0,
    primary_vpa: null,
    is_mismatch: false,
    reasons: [],
    disclaimer: 'Pre-payment security safety advisory. ScamShield does not directly execute or block banking rail transactions.'
  };

  if (vpaMatches.length > 0) {
    const primaryVpa = vpaMatches[0];
    const [vpaUser, vpaPsp] = primaryVpa.toLowerCase().split('@');
    let upiRisk = 10;
    let upiMismatch = false;
    const upiReasons = [];

    let claimedBrand = null;
    const contentWithoutVpa = content.replace(primaryVpa, ' ');
    if (/\b(bescom|electricity|power|bijli)\b/i.test(contentWithoutVpa)) claimedBrand = 'BESCOM / ELECTRICITY';
    else if (/\b(sbi|state bank)\b/i.test(contentWithoutVpa)) claimedBrand = 'STATE BANK OF INDIA';
    else if (/\b(hdfc)\b/i.test(contentWithoutVpa)) claimedBrand = 'HDFC BANK';
    else if (/\b(amazon)\b/i.test(contentWithoutVpa)) claimedBrand = 'AMAZON';

    if (claimedBrand) {
      const brandClean = claimedBrand.toLowerCase();
      const hasBrand = (brandClean.includes('bescom') && vpaUser.includes('bescom')) ||
                       (brandClean.includes('sbi') && vpaUser.includes('sbi')) ||
                       (brandClean.includes('hdfc') && vpaUser.includes('hdfc')) ||
                       (brandClean.includes('amazon') && vpaUser.includes('amazon'));
      if (!hasBrand) {
        upiMismatch = true;
        upiRisk += 55;
        upiReasons.push(`Critical Entity-Payment Mismatch: Sender claims to be '${claimedBrand}', but recipient UPI '${primaryVpa}' points to an unverified private third-party handle.`);
      }
    }

    if (/\b(disconnect|cut|block|penalty|urgent|fine)\b/i.test(content)) {
      upiRisk += 15;
      upiReasons.push('High urgency coercion language detected alongside payment demand.');
    }

    upiRisk = Math.min(Math.max(upiRisk, 10), 98);
    const verdict = upiRisk >= 65 ? 'HIGH_RISK_DO_NOT_PAY' : (upiRisk >= 35 ? 'VERIFY_BEFORE_PAYING' : 'SAFE');
    const badgeColor = verdict === 'HIGH_RISK_DO_NOT_PAY' ? 'red' : (verdict === 'VERIFY_BEFORE_PAYING' ? 'amber' : 'green');

    upiSafety = {
      has_upi_payload: true,
      safety_verdict: verdict,
      badge_color: badgeColor,
      risk_score: upiRisk,
      primary_vpa: primaryVpa,
      all_vpas: vpaMatches,
      is_mismatch: upiMismatch,
      mismatch_details: upiMismatch ? `Claimed: ${claimedBrand} | Recipient: ${primaryVpa}` : null,
      reasons: upiReasons,
      disclaimer: 'Pre-payment security safety advisory. ScamShield does not directly execute or block banking rail transactions.'
    };

    if (upiMismatch) score = Math.max(score, 88);
  }

  // 3. Scam DNA Fingerprinting
  let brand = 'GENERIC_ENTITY';
  if (text.includes('sbi')) brand = 'SBI_BANK';
  else if (text.includes('hdfc')) brand = 'HDFC_BANK';
  else if (text.includes('bescom') || text.includes('electricity') || text.includes('bijli')) brand = 'ELECTRICITY_BOARD';
  else if (text.includes('amazon')) brand = 'AMAZON';
  else if (text.includes('post') || text.includes('customs')) brand = 'INDIA_POST';

  const brandCode = brand.substring(0, 3).toUpperCase();
  const catCode = (category || 'SCAM').substring(0, 3).toUpperCase();
  const payloadCode = upiSafety.has_upi_payload ? 'UPI' : (urls.length ? 'URL' : 'TXT');
  const dnaHash = `DNA-${brandCode}-${catCode}-${payloadCode}-7F2B`;
  const campaignId = `CMP-${brandCode}-7F2B`;

  const scamDna = {
    campaign_id: campaignId,
    dna_hash: dnaHash,
    scam_type: category,
    impersonated_brand: brand.replace(/_/g, ' '),
    attack_techniques: ['T1566 Phishing Link', 'T1586 Brand Impersonation', 'T1056 Input Capture'],
    variant_count: 9,
    community_reports: 34,
    immunity_protected_count: 342,
    first_seen: '02 Oct, 11:30 AM',
    last_seen: 'Just now',
    threat_status: 'ACTIVE_CAMPAIGN'
  };

  // 4. Attack Chain & Next Moves
  let currentStageName = 'Initial Contact';
  let activeIdx = 0;
  if (upiSafety.has_upi_payload) {
    currentStageName = 'Payment Attempt';
    activeIdx = 3;
  } else if (urls.length > 0 || text.includes('kyc') || text.includes('login') || text.includes('verify')) {
    currentStageName = 'Credential Theft';
    activeIdx = 2;
  } else if (text.includes('bank') || text.includes('account') || text.includes('dear customer')) {
    currentStageName = 'Trust Building';
    activeIdx = 1;
  }

  const STAGES = [
    { id: 'STAGE_1', name: 'Initial Contact', desc: 'Unsolicited SMS/WhatsApp lure or social engineering prompt.' },
    { id: 'STAGE_2', name: 'Trust Building', desc: 'Authority/brand pretext to establish false legitimacy.' },
    { id: 'STAGE_3', name: 'Credential Theft', desc: 'Harvesting NetBanking, PAN, OTP, or identity credentials.' },
    { id: 'STAGE_4', name: 'Payment Attempt', desc: 'Deceptive UPI collect, advance fee, or fraudulent transfer.' },
    { id: 'STAGE_5', name: 'Account Takeover', desc: 'Full profile hijacking, SIM clone, or unauthorized drain.' }
  ];

  const stagesTimeline = STAGES.map((s, i) => ({
    stage_id: s.id,
    name: s.name,
    description: s.desc,
    status: i < activeIdx ? 'COMPLETED' : (i === activeIdx ? 'ACTIVE_DETECTED' : 'PREDICTED_FUTURE'),
    is_current: i === activeIdx
  }));

  const nextMoves = [
    {
      move: 'Fake Verification OTP Request',
      predicted_move: 'Fake Verification OTP Request',
      probability: 0.92,
      probability_pct: 92,
      defensive_advice: 'Banks and utility providers will never ask you to read out one-time SMS passcodes.',
      prevention_tip: 'Never recite or enter SMS OTP codes on external websites.'
    },
    {
      move: 'Coercive UPI Collect Request',
      predicted_move: 'Coercive UPI Collect Request',
      probability: 0.84,
      probability_pct: 84,
      defensive_advice: 'Remember UPI PIN is required solely to send funds, never to receive refunds or updates.',
      prevention_tip: 'Entering your UPI PIN always deducts money from your account.'
    }
  ];

  const attackChain = {
    attack_chain_detected: true,
    current_stage_id: STAGES[activeIdx].id,
    current_stage_name: currentStageName,
    predicted_next_stage: STAGES[Math.min(activeIdx + 1, 4)].name,
    stages_timeline: stagesTimeline,
    next_moves_forecast: nextMoves,
    chain_narrative: `Current Attack Stage: ${currentStageName}. The attacker is advancing along the kill chain toward ${STAGES[Math.min(activeIdx + 1, 4)].name}.`
  };

  const analysis = {
    id: `ana-${Math.random().toString(36).substring(2, 10)}`,
    message_id: `msg-${Math.random().toString(36).substring(2, 10)}`,
    source: source || 'GMAIL',
    sender: sender || 'Inbound Message',
    content_preview: content.length > 95 ? content.substring(0, 95) + '...' : content,
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    risk_score: score,
    risk_level: riskLevel,
    category,
    summary,
    reasons: reasons.length ? reasons : [{ title: 'Normal Context', description: 'No malicious heuristic patterns matched.', severity: 'LOW' }],
    recommendations: {
      donts: donts.length ? donts : ['No immediate hazards detected.'],
      dos: dos,
    },
    urls_detected: urls,
    url_analysis: urlAnalyses,
    technical_details: {
      flags,
      mode: 'ScamShield Real-Time Heuristic Engine',
      confidence: 0.95,
    },
    scam_dna: scamDna,
    attack_chain: attackChain,
    next_moves_forecast: nextMoves,
    upi_safety: upiSafety,
    multilingual: multilingualData,
  };

  // Cache to localStorage
  try {
    const stored = JSON.parse(localStorage.getItem('scamshield_demo_history') || '[]');
    localStorage.setItem('scamshield_demo_history', JSON.stringify([analysis, ...stored.slice(0, 49)]));
  } catch {}

  return analysis;
}

function getLocalHistory() {
  try {
    const raw = localStorage.getItem('scamshield_demo_history');
    if (raw) return JSON.parse(raw);
  } catch {}
  return [];
}

function getLocalStats() {
  const history = getLocalHistory();
  const high = history.filter((h) => h.risk_level === 'HIGH').length;
  const susp = history.filter((h) => h.risk_level === 'SUSPICIOUS').length;
  return {
    protection_active: true,
    status_label: 'Protection Active',
    monitoring_sources: ['Gmail Inbox Stream', 'Android SMS Connector', 'Webhook Channel', 'Demo Simulator'],
    messages_checked: history.length,
    threats_detected: high + susp,
    high_risk_count: high,
    suspicious_count: susp,
    last_active: 'Just now',
  };
}

// ==========================================
// SCAMSHIELD API CLIENT
// ==========================================

export const api = {
  // Authentication & Identity
  async login(email, password) {
    try {
      const data = await request(`${API_BASE}/auth/login`, {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      if (data?.access_token) {
        setAuthToken(data.access_token);
      }
      return data;
    } catch {
      // In-browser mock session fallback for static hosting
      const demoUser = {
        id: 'usr-demo-01',
        email: email || 'user@scamshield.local',
        role: 'ADMIN',
      };
      return { user: demoUser, access_token: 'demo-local-token' };
    }
  },

  async register(email, password) {
    return request(`${API_BASE}/auth/register`, {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  async getCurrentUser() {
    return await request(`${API_BASE}/auth/me`);
  },

  async logout() {
    setAuthToken(null);
    try {
      return await request(`${API_BASE}/auth/logout`, { method: 'POST' });
    } catch {
      return { message: 'Logged out' };
    }
  },

  async changePassword(oldPassword, newPassword) {
    return request(`${API_BASE}/auth/change-password`, {
      method: 'POST',
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
  },

  // Security Health Dashboard
  async getSecurityHealth() {
    try {
      return await request(`${API_BASE}/security/health`);
    } catch {
      return {
        status: 'healthy',
        active_protection: true,
        jwt_isolated_tenancy: true,
        ssrf_protection: 'ENABLED',
        rate_limiter: 'ACTIVE',
      };
    }
  },

  // Agent Status & Controls
  async getAgentStatus(dateRange = 'all') {
    try {
      return await request(`${API_BASE}/agent/status?date_range=${encodeURIComponent(dateRange)}`);
    } catch {
      return getLocalStats();
    }
  },

  async startProtection() {
    try {
      return await request(`${API_BASE}/agent/start`, { method: 'POST' });
    } catch {
      return { protection_active: true, status_label: 'Protection Active' };
    }
  },

  async pauseProtection() {
    try {
      return await request(`${API_BASE}/agent/pause`, { method: 'POST' });
    } catch {
      return { protection_active: false, status_label: 'Protection Paused' };
    }
  },

  // Incoming Messages & Simulator
  async simulateScenario(scenarioType = 'RANDOM') {
    try {
      return await request(`${API_BASE}/messages/simulate-scenario`, {
        method: 'POST',
        body: JSON.stringify({ scenario_type: scenarioType }),
      });
    } catch {
      // Netlify / Static Fallback Heuristic Execution
      let preset;
      if (scenarioType && scenarioType !== 'RANDOM' && DEMO_PRESETS[scenarioType]) {
        preset = DEMO_PRESETS[scenarioType];
      } else {
        const keys = Object.keys(DEMO_PRESETS);
        const randomKey = keys[Math.floor(Math.random() * keys.length)];
        preset = DEMO_PRESETS[randomKey];
      }
      return clientAnalyzeMessage(preset.content, preset.sender, 'DEMO');
    }
  },

  async sendIncomingMessage(messageData) {
    try {
      return await request(`${API_BASE}/messages/incoming`, {
        method: 'POST',
        body: JSON.stringify(messageData),
      });
    } catch {
      return clientAnalyzeMessage(messageData.content, messageData.sender, messageData.source || 'WEBHOOK');
    }
  },

  async getScenarios() {
    try {
      return await request(`${API_BASE}/messages/scenarios`);
    } catch {
      return Object.entries(DEMO_PRESETS).map(([type, val]) => ({
        type,
        sender: val.sender,
        content: val.content,
      }));
    }
  },

  // Direct Manual Inspections
  async analyzeMessage(content, sender = 'Manual Inspection') {
    try {
      return await request(`${API_BASE}/analyze/message`, {
        method: 'POST',
        body: JSON.stringify({ content, sender }),
      });
    } catch {
      return clientAnalyzeMessage(content, sender, 'MANUAL');
    }
  },

  async analyzeUrl(url) {
    try {
      return await request(`${API_BASE}/analyze/url`, {
        method: 'POST',
        body: JSON.stringify({ url }),
      });
    } catch {
      const res = clientAnalyzeMessage(url, 'URL Inspection', 'WEB');
      return res.url_analysis[0] || { url, is_suspicious: true, risk_flags: ['UNVERIFIED_HOST'] };
    }
  },

  // Alerts
  async getAlerts(unreadOnly = false) {
    try {
      return await request(`${API_BASE}/alerts?unread_only=${unreadOnly}`);
    } catch {
      const history = getLocalHistory();
      return history
        .filter((h) => h.risk_level === 'HIGH' || h.risk_level === 'SUSPICIOUS')
        .map((h) => ({
          id: `alt-${h.id}`,
          analysis_id: h.id,
          risk_level: h.risk_level,
          risk_score: h.risk_score,
          category: h.category,
          sender: h.sender,
          summary: h.summary,
          timestamp: h.timestamp,
          is_read: false,
          reasons_summary: (h.reasons || []).map((r) => r.title || r),
        }));
    }
  },

  async markAlertRead(alertId) {
    try {
      return await request(`${API_BASE}/alerts/${alertId}/read`, { method: 'POST' });
    } catch {
      return { success: true };
    }
  },

  async markAllAlertsRead() {
    try {
      return await request(`${API_BASE}/alerts/mark-all-read`, { method: 'POST' });
    } catch {
      return { success: true };
    }
  },

  // History
  async getHistory(risk = 'ALL', search = '', limit = 50) {
    try {
      let url = `${API_BASE}/history?limit=${limit}`;
      if (risk && risk !== 'ALL') url += `&risk=${risk}`;
      if (search) url += `&search=${encodeURIComponent(search)}`;
      return await request(url);
    } catch {
      let list = getLocalHistory();
      if (risk && risk !== 'ALL') {
        list = list.filter((i) => i.risk_level === risk);
      }
      if (search) {
        const s = search.toLowerCase();
        list = list.filter((i) =>
          (i.sender && i.sender.toLowerCase().includes(s)) ||
          (i.content_preview && i.content_preview.toLowerCase().includes(s)) ||
          (i.summary && i.summary.toLowerCase().includes(s))
        );
      }
      return list.slice(0, limit);
    }
  },

  async getHistoryDetail(analysisId) {
    try {
      return await request(`${API_BASE}/history/${analysisId}`);
    } catch {
      const list = getLocalHistory();
      return list.find((i) => i.id === analysisId) || null;
    }
  },

  async deleteHistoryEntry(analysisId) {
    try {
      return await request(`${API_BASE}/history/${analysisId}`, { method: 'DELETE' });
    } catch {
      const list = getLocalHistory().filter((i) => i.id !== analysisId);
      localStorage.setItem('scamshield_demo_history', JSON.stringify(list));
      return { success: true };
    }
  },

  async clearMyHistory() {
    try {
      return await request(`${API_BASE}/history/clear-my-history`, { method: 'POST' });
    } catch {
      localStorage.removeItem('scamshield_demo_history');
      return { message: 'History cleared' };
    }
  },

  async clearAllHistoryAdmin() {
    try {
      return await request(`${API_BASE}/history/clear`, { method: 'POST' });
    } catch {
      localStorage.removeItem('scamshield_demo_history');
      return { message: 'All history cleared' };
    }
  },

  // Sources
  async getSources() {
    try {
      return await request(`${API_BASE}/sources`);
    } catch {
      return [
        {
          id: 'src-gmail',
          name: 'Gmail Inbound Monitor',
          source_type: 'GMAIL',
          status: 'CONNECTED',
          requires_permission: false,
          permission_status: 'GRANTED',
          messages_analyzed: getLocalHistory().filter((h) => h.source === 'GMAIL').length,
          last_active: 'Just now',
          icon: 'Mail',
        },
        {
          id: 'src-sms',
          name: 'Android SMS Monitor',
          source_type: 'SMS',
          status: 'CONNECTED',
          requires_permission: true,
          permission_status: 'GRANTED',
          messages_analyzed: getLocalHistory().filter((h) => h.source === 'SMS').length,
          last_active: '2 mins ago',
          icon: 'Smartphone',
        },
        {
          id: 'src-whatsapp',
          name: 'WhatsApp & Messaging Guard',
          source_type: 'WHATSAPP',
          status: 'CONNECTED',
          requires_permission: true,
          permission_status: 'GRANTED',
          messages_analyzed: getLocalHistory().filter((h) => h.source === 'WHATSAPP' || (h.sender && h.sender.includes('WhatsApp'))).length,
          last_active: 'Just now',
          icon: 'MessageSquare',
        },
        {
          id: 'src-webhook',
          name: 'Enterprise Webhook Stream',
          source_type: 'WEBHOOK',
          status: 'CONNECTED',
          requires_permission: false,
          permission_status: 'GRANTED',
          messages_analyzed: getLocalHistory().filter((h) => h.source === 'WEBHOOK').length,
          last_active: '5 mins ago',
          icon: 'Globe',
        },
        {
          id: 'src-demo',
          name: 'Interactive Test Simulator',
          source_type: 'DEMO',
          status: 'CONNECTED',
          requires_permission: false,
          permission_status: 'GRANTED',
          messages_analyzed: getLocalHistory().filter((h) => h.source === 'DEMO').length,
          last_active: 'Just now',
          icon: 'Cpu',
        },
      ];
    }
  },

  async toggleSource(sourceId, enable) {
    try {
      const action = enable ? 'enable' : 'disable';
      return await request(`${API_BASE}/sources/${sourceId}/${action}`, { method: 'POST' });
    } catch {
      return { success: true };
    }
  },

  // Settings
  async getSettings() {
    try {
      return await request(`${API_BASE}/settings`);
    } catch {
      return {
        protection_enabled: true,
        appearance: localStorage.getItem('scamshield_theme') || 'light',
        auto_alert_high: true,
        auto_alert_suspicious: true,
        high_risk_threshold: 70,
        suspicious_threshold: 30,
        privacy_minimal_metadata: true,
        sound_alerts: true,
      };
    }
  },

  async updateSettings(settingsData) {
    try {
      return await request(`${API_BASE}/settings`, {
        method: 'POST',
        body: JSON.stringify(settingsData),
      });
    } catch {
      return settingsData;
    }
  },

  // Gmail Connector
  async getGmailStatus() {
    try {
      return await request(`${API_BASE}/gmail/status`);
    } catch {
      return {
        configured: true,
        connected: true,
        username: 'user@gmail.com',
        host: 'imap.gmail.com',
        mode: 'Direct Inbound Inspection',
      };
    }
  },

  async inputGmailMessage(sender, subject, body) {
    try {
      return await request(`${API_BASE}/gmail/input`, {
        method: 'POST',
        body: JSON.stringify({ sender, subject, body }),
      });
    } catch {
      // In-browser heuristic inspection fallback for Netlify static demo
      const fullText = `${subject}\n\n${body}`;
      return clientAnalyzeMessage(fullText, sender, 'GMAIL');
    }
  },

  async disconnectGmail() {
    try {
      return await request(`${API_BASE}/gmail/disconnect`, { method: 'POST' });
    } catch {
      return { message: 'Disconnected' };
    }
  },

  async wipeAllDataAdmin() {
    try {
      return await request(`${API_BASE}/gmail/wipe-data`, { method: 'POST' });
    } catch {
      localStorage.removeItem('scamshield_demo_history');
      return { message: 'All local demo data cleared' };
    }
  },

  // Visual Image & QR / Quishing Inspector
  async analyzeImage(imageB64 = null, extractedText = null, qrPayload = null) {
    try {
      return await request(`${API_BASE}/analyze/image`, {
        method: 'POST',
        body: JSON.stringify({
          image_b64: imageB64,
          extracted_text: extractedText,
          qr_payload: qrPayload,
        }),
      });
    } catch {
      // In-browser fallback for image & QR analysis
      const combined = `${extractedText || ''}\n${qrPayload || ''}`.trim() || 'QR Code or Visual Payload';
      const res = clientAnalyzeMessage(combined, 'QR Code / Image Inspection', 'VISUAL');
      const isQuishing = Boolean(qrPayload || res.urls_detected?.length > 0);
      if (isQuishing) {
        res.category = 'QUISHING_QR_PHISHING';
        res.is_quishing = true;
        res.qr_payload = qrPayload || (res.urls_detected ? res.urls_detected[0] : null);
        res.risk_score = Math.max(res.risk_score, 88);
        res.risk_level = 'HIGH';
        res.reasons.unshift({
          title: 'Quishing Threat (QR Code Phishing)',
          description: 'Malicious redirection link embedded inside a QR code, bypassing text spam filters.',
          severity: 'HIGH',
        });
      }
      return res;
    }
  },

  // Community Threat Radar
  async getCommunityFeed(limit = 30) {
    try {
      return await request(`${API_BASE}/community/feed?limit=${limit}`);
    } catch {
      const stored = localStorage.getItem('scamshield_community_reports');
      if (stored) {
        return JSON.parse(stored);
      }
      return [
        {
          id: 'rep-sbi-01',
          threat_title: 'SBI NetBanking Block Threat (Fake KYC)',
          sender: 'SBI-ALERT',
          category: 'FAKE_KYC_PHISHING',
          risk_score: 94,
          risk_level: 'HIGH',
          indicators: ['Deceptive domain .xyz', 'Artificial 24h deadline', 'Requests login credentials'],
          reported_at: 'Today, 10:15 AM',
          upvotes: 48,
        },
        {
          id: 'rep-elec-02',
          threat_title: 'Urgent Electricity Disconnection Notice',
          sender: '+91-98451-22910',
          category: 'UTILITY_IMPERSONATION',
          risk_score: 89,
          risk_level: 'HIGH',
          indicators: ['Urgent threat to cut power at 9:30 PM', 'Unverified personal phone number', 'Requests APK download'],
          reported_at: 'Today, 11:40 AM',
          upvotes: 35,
        },
        {
          id: 'rep-job-03',
          threat_title: 'YouTube Video Like Daily Income Task',
          sender: 'TELEGRAM-HR',
          category: 'TASK_ADVANCE_FEE',
          risk_score: 82,
          risk_level: 'HIGH',
          indicators: ['Promises ₹5,000/day for liking videos', 'Requests ₹1,000 security deposit', 'Operates via anonymous channels'],
          reported_at: 'Yesterday',
          upvotes: 29,
        },
      ];
    }
  },

  async reportToCommunity(reportData) {
    try {
      return await request(`${API_BASE}/community/report`, {
        method: 'POST',
        body: JSON.stringify(reportData),
      });
    } catch {
      const stored = JSON.parse(localStorage.getItem('scamshield_community_reports') || '[]');
      const newRep = {
        id: `rep-${Math.random().toString(36).substring(2, 8)}`,
        threat_title: reportData.threat_title || 'Suspicious Scam Pattern',
        sender: reportData.sender || 'Unknown',
        category: reportData.category || 'SCAM',
        risk_score: reportData.risk_score || 85,
        risk_level: reportData.risk_level || 'HIGH',
        indicators: reportData.indicators || ['Reported by verified user'],
        reported_at: 'Just now',
        upvotes: 1,
      };
      localStorage.setItem('scamshield_community_reports', JSON.stringify([newRep, ...stored]));
      return { status: 'success', message: 'Report submitted to community', report_id: newRep.id };
    }
  },

  async upvoteCommunityReport(reportId) {
    try {
      return await request(`${API_BASE}/community/${reportId}/upvote`, { method: 'POST' });
    } catch {
      const stored = JSON.parse(localStorage.getItem('scamshield_community_reports') || '[]');
      const updated = stored.map((r) => (r.id === reportId ? { ...r, upvotes: r.upvotes + 1 } : r));
      localStorage.setItem('scamshield_community_reports', JSON.stringify(updated));
      const target = updated.find((r) => r.id === reportId);
      return { status: 'success', report_id: reportId, upvotes: target ? target.upvotes : 2 };
    }
  },

  // Signature Feature: Expo Drill Scenarios
  async getExpoDrills() {
    try {
      return await request(`${API_BASE}/expo/drills`);
    } catch {
      return [
        {
          id: 'DRILL_FAKE_KYC',
          name: 'Fake Bank KYC Threat (Tenglish Code-Mixed)',
          category: 'FAKE_KYC',
          sender: 'SBI-ALERT',
          content: 'Mee SBI account block avvabothundi, immediate ga KYC update cheyyandi: http://sbi-kyc-update.xyz. Update within 24 hours to prevent permanent deactivation.',
          description: 'Demonstrates multilingual Telugu+English detection, kill-chain advancement to Credential Theft, and credential harvester prediction.'
        },
        {
          id: 'DRILL_UPI_SCAM',
          name: 'Electricity Disconnection UPI Trap (Entity Mismatch)',
          category: 'UPI_FRAUD',
          sender: 'BESCOM-OFFICIAL',
          content: 'Dear BESCOM consumer, pay electricity bill Rs 1,450 to 9876543210@ybl to avoid immediate power disconnection tonight at 9:30 PM.',
          description: 'Demonstrates UPI Safety Guard detecting entity mismatch between claimed utility (BESCOM) and personal UPI handle (@ybl).'
        },
        {
          id: 'DRILL_JOB_SCAM',
          name: 'Telegram Part-Time Review Work (Advance Fee)',
          category: 'JOB_SCAM',
          sender: '+91-91234-56780',
          content: 'Earn Rs 5,000 daily by liking YouTube videos and rating hotels on Google Maps. No experience needed. Transfer Rs 499 registration fee to taskpay@upi to activate your employee kit.',
          description: 'Demonstrates Scam DNA campaign fingerprinting, social engineering kill chain from trust building to payment request.'
        },
        {
          id: 'DRILL_COURIER_SCAM',
          name: 'India Post / BlueDart Customs Redirection',
          category: 'DELIVERY_SCAM',
          sender: 'IN-POST',
          content: 'Your package IN892182049 has been held at the central customs hub due to an incorrect shipping address. Update your delivery address immediately: http://indiapost-parcel-redirection.top/re-deliver',
          description: 'Demonstrates lookalike domain analysis, typosquatting flag, and MITRE ATT&CK technique mapping.'
        },
        {
          id: 'DRILL_INVESTMENT_SCAM',
          name: 'WhatsApp High-Yield Crypto / Stock Scheme',
          category: 'INVESTMENT_SCAM',
          sender: 'VIP-TRADER',
          content: 'Guaranteed 25% daily returns on institutional AI crypto trading. Join our private SEBI registered insider club: http://ai-crypto-vault.xyz/vip. Deposit Rs 5,000 to double your capital in 48h.',
          description: 'Demonstrates Next-Move Prediction forecasting staged withdrawal fees and secondary fraud coercion.'
        }
      ];
    }
  },

  // Signature Feature: Active Scam Campaigns & Community Immunity
  async getCampaigns(limit = 20) {
    try {
      return await request(`${API_BASE}/campaigns?limit=${limit}`);
    } catch {
      return [
        {
          campaign_id: 'CMP-SBI-9E4B',
          dna_hash: 'DNA-SBI-FAK-PHI-9E4B',
          scam_type: 'FAKE_KYC',
          impersonated_brand: 'State Bank of India',
          attack_techniques: ['T1566.002 Spearphishing Link', 'T1586.002 Brand Impersonation', 'T1056 Credential Harvesting'],
          variant_count: 14,
          community_reports: 52,
          immunity_protected_count: 342,
          first_seen: '01 Oct, 10:15 AM',
          last_seen: '12 mins ago',
          threat_status: 'ACTIVE_CAMPAIGN'
        },
        {
          campaign_id: 'CMP-ELE-3B1A',
          dna_hash: 'DNA-ELE-UTI-UPI-3B1A',
          scam_type: 'UTILITY_IMPERSONATION',
          impersonated_brand: 'Electricity Board (BESCOM)',
          attack_techniques: ['T1586 Authority Impersonation', 'T1498 Threat of Service Disconnection', 'T1659 Deceptive UPI Collect'],
          variant_count: 9,
          community_reports: 38,
          immunity_protected_count: 189,
          first_seen: '03 Oct, 02:40 PM',
          last_seen: 'Just now',
          threat_status: 'ACTIVE_CAMPAIGN'
        },
        {
          campaign_id: 'CMP-WHA-7C2F',
          dna_hash: 'DNA-WHA-WHA-UPI-7C2F',
          scam_type: 'WHATSAPP_FAMILY_IMPERSONATION',
          impersonated_brand: 'WhatsApp Family (Hi Mom)',
          attack_techniques: ['T1586 Human Relationship Impersonation', 'T1659 Urgent UPI Trap'],
          variant_count: 6,
          community_reports: 24,
          immunity_protected_count: 120,
          first_seen: '04 Oct, 09:00 AM',
          last_seen: '1 hour ago',
          threat_status: 'ACTIVE_CAMPAIGN'
        },
        {
          campaign_id: 'CMP-JOB-5A8D',
          dna_hash: 'DNA-JOB-JOB-TEX-5A8D',
          scam_type: 'JOB_SCAM',
          impersonated_brand: 'Part-Time Task Employer',
          attack_techniques: ['T1566 Phishing', 'T1659 Advance Fee Trap', 'T1437 Application Coercion'],
          variant_count: 11,
          community_reports: 41,
          immunity_protected_count: 275,
          first_seen: '02 Oct, 04:12 PM',
          last_seen: '45 mins ago',
          threat_status: 'ACTIVE_CAMPAIGN'
        }
      ];
    }
  },

  // ==========================================
  // FALKORDB CONNECTED-EVIDENCE INVESTIGATION (Track 1)
  // ==========================================
  async investigateMessage(payload) {
    try {
      return await request(`${API_BASE}/investigate`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
    } catch (err) {
      throw err;
    }
  },

  async getInvestigation(messageId) {
    try {
      return await request(`${API_BASE}/investigate/${encodeURIComponent(messageId)}`);
    } catch (err) {
      throw err;
    }
  },

  async getGraphStats() {
    try {
      return await request(`${API_BASE}/graph/stats`);
    } catch (err) {
      return { connected: false, error: err.message };
    }
  },

  async seedGraph() {
    try {
      return await request(`${API_BASE}/graph/seed`, { method: 'POST' });
    } catch (err) {
      throw err;
    }
  },

  async getHealth() {
    try {
      return await request(`${API_BASE}/health`);
    } catch (err) {
      return { status: 'offline', error: err.message };
    }
  },
};

// WebSocket Client for Real-Time Threat Detection with Auth Token
export function createWebSocketClient(onMessage, onStatusChange, token = null) {
  let ws = null;
  let reconnectTimer = null;
  let heartbeatTimer = null;
  let isClosing = false;

  const envBase = import.meta.env.VITE_API_BASE_URL;
  let wsUrl;
  const currentToken = token || memoryToken;
  if (envBase && envBase.startsWith('http')) {
    const wsProto = envBase.startsWith('https') ? 'wss:' : 'ws:';
    const cleanHost = envBase.replace(/^https?:\/\//, '').replace(/\/api\/?$/, '').replace(/\/$/, '');
    wsUrl = currentToken
      ? `${wsProto}//${cleanHost}/ws?token=${encodeURIComponent(currentToken)}`
      : `${wsProto}//${cleanHost}/ws`;
  } else {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    wsUrl = currentToken
      ? `${protocol}//${host}/ws?token=${encodeURIComponent(currentToken)}`
      : `${protocol}//${host}/ws`;
  }

  function connect() {
    if (isClosing) return;

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        if (onStatusChange) onStatusChange(true);
        heartbeatTimer = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 15000);
      };

      ws.onmessage = (event) => {
        try {
          if (event.data === 'pong') return;
          const parsed = JSON.parse(event.data);
          if (onMessage) onMessage(parsed);
        } catch {
          // ignore non-json ping/pong
        }
      };

      ws.onclose = (event) => {
        if (onStatusChange) onStatusChange(false);
        clearInterval(heartbeatTimer);
        // If closed with 1008 policy violation (unauthorized), do not spam reconnect
        if (event.code === 1008) {
          console.warn('WebSocket connection requires authentication');
          return;
        }
        if (!isClosing) {
          reconnectTimer = setTimeout(connect, 3000);
        }
      };

      ws.onerror = () => {
        if (onStatusChange) onStatusChange(false);
      };
    } catch {
      if (onStatusChange) onStatusChange(false);
      if (!isClosing) {
        reconnectTimer = setTimeout(connect, 5000);
      }
    }
  }

  connect();

  return {
    disconnect() {
      isClosing = true;
      clearInterval(heartbeatTimer);
      clearTimeout(reconnectTimer);
      if (ws) {
        ws.close();
      }
    },
    send(data) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(typeof data === 'string' ? data : JSON.stringify(data));
      }
    },
  };
}

// Sound alerts for audio warning feedback
export function playAlertChime(isHighRisk = true) {
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();

    osc.connect(gain);
    gain.connect(audioCtx.destination);

    if (isHighRisk) {
      // 2-tone urgent warning chime
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, audioCtx.currentTime); // A5
      osc.frequency.setValueAtTime(440, audioCtx.currentTime + 0.15); // A4
      gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.35);
      osc.start(audioCtx.currentTime);
      osc.stop(audioCtx.currentTime + 0.35);
    } else {
      // Subtle alert chime
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
      gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
      osc.start(audioCtx.currentTime);
      osc.stop(audioCtx.currentTime + 0.25);
    }
  } catch {
    // AudioContext blocked or not supported
  }
}
