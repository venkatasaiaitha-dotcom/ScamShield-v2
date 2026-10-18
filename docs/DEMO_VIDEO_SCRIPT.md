# 🎬 ScamShield Graph — Demonstration Video Script

**Target Duration:** ~3 to 4 minutes  
**Track:** Track 1: Agents That Act on Connected Data (WeMakeDevs Graph Hacks 2026, Powered by FalkorDB)  
**Presenter:** Aitha Venkata Sai  

---

## ⏱️ Video Breakdown

### Part 1: The Cybersecurity Problem (0:00 – 0:45)
* **Visual:** Open browser on ScamShield Graph Dashboard (`http://127.0.0.1:8000`).
* **Speaker:**
  > "Hello everyone! Welcome to ScamShield Graph, built for Track 1 of Graph Hacks 2026 by WeMakeDevs, powered by FalkorDB.
  >
  > Today's cyber scam syndicates don't just send one message. They launch coordinated campaigns reusing malicious infrastructure: spoofed bank domains, disposable numbers, and advance-fee templates.
  >
  > Traditional spam detectors look at one message in isolation. If an attacker phrases an email politely, traditional NLP might call it safe. They have zero memory of cross-channel infrastructure.
  >
  > ScamShield Graph solves this by pairing proactive message analysis with an autonomous FalkorDB Graph Investigation Agent."

---

### Part 2: Submitting the Synthetic Message (0:45 – 1:30)
* **Visual:** On the Dashboard, navigate to the Simulator bar. Click **1. Fake Bank KYC Phishing (Multi-Stage Kill Chain)**.
* **Speaker:**
  > "Let's demonstrate this with an end-to-end scenario. Here's a simulated SMS from 'SBI-ALERT' claiming our net banking KYC has expired, directing us to `http://sbi-kyc-verify-portal.in/login`.
  >
  > As soon as this message is received, ScamShield immediately alerts us: Risk Score 96/100, High Alert.
  >
  > But rather than just telling us what the text looks like, let's click: **'Investigate Connected Evidence'**."

---

### Part 3: FalkorDB Graph Traversal & Tool Invocation (1:30 – 2:30)
* **Visual:** The Alert Modal expands, displaying the **FalkorDB Graph Investigation** card. Click on nodes in the visual entity-relationship canvas.
* **Speaker:**
  > "Under the hood, our FastAPI backend invoked our Autonomous Investigation Agent.
  >
  > The agent tokenized the message into the FalkorDB knowledge graph named `scamshield`.
  >
  > Then, using dedicated graph tools, it executed parameterized Cypher queries:
  > 1. First, `find_shared_indicators` traversed the graph to see if `sbi-kyc-verify-portal.in` has been seen before. FalkorDB instantly revealed **two other historical messages** in the database targeting different victims with PAN card linking and suspension threats using this identical domain!
  > 2. Second, `trace_connected_evidence` traversed multi-hop edges to identify associated threat intelligence. The domain directly connects to `REP_SYNTH_KYC_01` — a synthetic banking impersonation advisory.
  > 3. Third, it flagged an organizational mismatch: the message claims to represent 'State Bank of India', yet routes authentication through an unverified third-party domain."

---

### Part 4: The Agent's Grounded Explanation & Uncertainty (2:30 – 3:15)
* **Visual:** Highlight the **Agent Graph-Grounded Investigation Summary** text and the **Methodological Disclosure** banner.
* **Speaker:**
  > "Notice the explanation: every single statement is grounded strictly in facts returned by FalkorDB's Cypher engine. No hallucinations, no invented links.
  >
  > Crucially, as responsible AI practitioners, our agent includes an explicit uncertainty disclosure:
  > *'A shared domain or phone number is an investigative lead for pattern clustering, not definitive automated proof of fraud.'*
  >
  > This empowers security analysts with clear evidence while avoiding false-positive overconfidence."

---

### Part 5: Resilience, Tests & Closing (3:15 – 3:45)
* **Visual:** Switch briefly to the terminal showing all 33 pytest tests passing (`python -m pytest backend/tests/ -v`).
* **Speaker:**
  > "ScamShield Graph is fully tested with 33 passing automated tests, idempotent seeding, and graceful 503 error handling if the database is offline.
  >
  > By transforming isolated message detection into a graph-connected investigation agent, FalkorDB enables proactive, explainable cyber defense at machine speed.
  >
  > Thank you WeMakeDevs and FalkorDB!"
