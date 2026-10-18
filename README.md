# 🛡️ ScamShield Graph — AI-Powered Connected Scam Investigation Agent

> **Graph Hacks 2026 Submission**  
> **Track 1:** Agents That Act on Connected Data  
> **Powered by:** [FalkorDB](https://www.falkordb.com/) & [FastAPI](https://fastapi.tiangolo.com/) + [React](https://react.dev/)

---

## 🌟 Executive Overview & Problem Statement

Modern cyber fraudsters rarely launch completely isolated attacks. Instead, organized syndicates operate across distributed channels, repeatedly reusing core attack infrastructure: **lookalike domains, virtual phone numbers, UPI payment addresses, and social engineering templates**.

Traditional spam filters and standalone NLP detectors analyze incoming messages in isolation:
* If a text has subtle or novel wording, an isolated detector may score it as low or moderate risk.
* An isolated detector **cannot see** that the embedded link was used 10 minutes ago in another impersonation attack or that the sender's phone number is linked to an active threat advisory.

**ScamShield Graph** bridges this critical defense gap. It combines ScamShield's proactive incoming message detection with an autonomous **FalkorDB Graph Investigation Agent**. By modeling incoming communications, indicators, entities, and threat reports in a Cypher knowledge graph, ScamShield Graph reveals the hidden connections behind every message.

---

## 🏗️ Architecture & Investigation Flow

```
+-----------------------------------------------------------------------------------------+
|                                    USER INTERACTION                                     |
|     Incoming Message (SMS / Gmail IMAP / Webhook / Expo Cyber Drill / Manual Studio)     |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                                   FASTAPI BACKEND                                       |
|  1. Ingestion & Normalization ──► 2. Hybrid NLP & Multi-Vector Analyzer                  |
|     (Extracts URLs, Domains, Phones, VPAs, Claimed Brands, Threat Indicators)           |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                        FALKORDB KNOWLEDGE GRAPH ENGINE ('scamshield')                   |
|  3. Idempotent Ingestion Hook: MERGE (:Message)-[:CONTAINS|MENTIONS]->(:Entity)         |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                         AUTONOMOUS INVESTIGATION AGENT & TOOLS                          |
|  - Tool 1: find_shared_indicators(message_id) ──► Parameterized Cypher Queries          |
|  - Tool 2: trace_connected_evidence(message_id) ──► Multi-Hop Path Traversal            |
|  - Tool 3: get_evidence_summary(message_id) ──► Synthesizes Grounded Graph Findings     |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                                    REACT FRONTEND UI                                    |
|  - Real-time Alert Modal with "Investigate Connected Evidence" Action                   |
|  - Interactive Entity-Relationship Graph Visualization Canvas                           |
|  - Shared Indicators Across Historical Messages Panel                                   |
|  - Threat Intelligence Provenance Badges (SYNTHETIC_BENCHMARK / VERIFIED_ADVISORY)      |
|  - Grounded Plain-English Explanation with Explicit Uncertainty Disclosures             |
+-----------------------------------------------------------------------------------------+
```

---

## 🕸️ Knowledge Graph Schema

The application uses a dedicated FalkorDB graph named **`scamshield`**:

```
               ┌───────────────────────┐
               │     Organization      │
               │ (name, category, ...) │
               └───────────▲───────────┘
                           │ [:CLAIMS_TO_REPRESENT]
                           │
 ┌─────────────┐   [:CONTAINS]   ┌─────────────┐  [:HOSTED_ON]   ┌─────────────┐
 │   Message   │────────────────►│     URL     │────────────────►│   Domain    │
 └──────┬──────┘                 └─────────────┘                 └──────┬──────┘
        │                                                               │
        │ [:MENTIONS]                                                   │ [:ASSOCIATED_
        ▼                                                               │   WITH_REPORT]
 ┌─────────────┐                                                        │
 │    Phone    │──────────────────────────────────────┐                 │
 └─────────────┘        [:ASSOCIATED_WITH_REPORT]      │                 ▼
        │                                             ▼          ┌─────────────┐
        │ [:HAS_INDICATOR]                       ┌─────────┐     │   Report    │
        ▼                                        │ Report  │◄────│ (title,     │
 ┌─────────────┐          [:RELATED_TO]          └─────────┘     │  source,    │
 │  Indicator  │────────────────────────────────────────────────►│  status,...)│
 └─────────────┘                                                 └─────────────┘
```

### Node Types
* **`Message`**: `id`, `sender`, `content_preview`, `risk_score`, `risk_level`, `category`, `timestamp`, `is_synthetic`
* **`Domain`**: `name`, `is_typosquat`, `is_suspicious_tld`, `target_brand`
* **`URL`**: `url`, `is_ip`, `is_shortener`, `risk_score`
* **`Phone`**: `number`, `country_code`
* **`Organization`**: `name`, `category`
* **`Indicator`**: `id`, `name`, `description`, `severity`
* **`Report`**: `id`, `title`, `source`, `verification_status`, `severity`, `summary`, `date`

### Relationships
* `(:Message)-[:CONTAINS]->(:URL)`
* `(:URL)-[:HOSTED_ON]->(:Domain)`
* `(:Message)-[:MENTIONS]->(:Phone)`
* `(:Message)-[:CLAIMS_TO_REPRESENT]->(:Organization)`
* `(:Message)-[:HAS_INDICATOR]->(:Indicator)`
* `(:Domain)-[:ASSOCIATED_WITH_REPORT]->(:Report)`
* `(:Phone)-[:ASSOCIATED_WITH_REPORT]->(:Report)`
* `(:Indicator)-[:RELATED_TO]->(:Report)`

---

## 🔎 Meaningful Cypher Investigations

### Investigation A: Shared Adversarial Indicators
Identifies other messages in the database that share an identical domain, phone number, or indicator:
```cypher
MATCH (m:Message {id: $msg_id})-[r1:CONTAINS|MENTIONS|HAS_INDICATOR]->(shared)<-[r2:CONTAINS|MENTIONS|HAS_INDICATOR]-(other:Message)
WHERE other.id <> m.id
RETURN
    coalesce(shared.name, shared.url, shared.number, shared.id) AS indicator_val,
    labels(shared) AS indicator_labels,
    type(r1) AS relationship,
    other.id AS other_id,
    other.sender AS other_sender,
    other.content_preview AS other_preview,
    other.risk_score AS other_risk_score,
    other.category AS other_category,
    other.timestamp AS other_timestamp
LIMIT 15
```

### Investigation B: Connected Threat Intelligence
Traces multi-hop relationships from the submitted message to external threat advisories or benchmark records:
```cypher
MATCH (m:Message {id: $msg_id})
OPTIONAL MATCH (m)-[:CONTAINS]->(u:URL)-[:HOSTED_ON]->(d:Domain)
OPTIONAL MATCH (m)-[:MENTIONS]->(p:Phone)
OPTIONAL MATCH (m)-[:CLAIMS_TO_REPRESENT]->(o:Organization)
OPTIONAL MATCH (m)-[:HAS_INDICATOR]->(i:Indicator)
OPTIONAL MATCH (d)-[:ASSOCIATED_WITH_REPORT]->(dr:Report)
OPTIONAL MATCH (p)-[:ASSOCIATED_WITH_REPORT]->(pr:Report)
OPTIONAL MATCH (i)-[:RELATED_TO]->(ir:Report)
RETURN m, collect(DISTINCT d.name) AS domains,
       collect(DISTINCT p.number) AS phones,
       collect(DISTINCT o.name) AS organizations,
       collect(DISTINCT i.name) AS indicators,
       collect(DISTINCT dr) + collect(DISTINCT pr) + collect(DISTINCT ir) AS reports
```

---

## ⚡ Quick Start & Installation

### 1. Prerequisites
* Python 3.10+ (Tested on Python 3.14)
* Node.js 18+ & npm
* Docker (Optional for local FalkorDB container) or FalkorDB Cloud account

### 2. Run FalkorDB
Launch the official FalkorDB Docker container:
```bash
docker run -p 6379:6379 -d --name falkordb falkordb/falkordb:latest
```
*Alternatively, use docker-compose:*
```bash
docker compose up -d
```
*(If FalkorDB is running on a remote host or FalkorDB Cloud, specify `FALKORDB_HOST`, `FALKORDB_PORT`, and `FALKORDB_PASSWORD` in your `.env` file.)*

### 3. Install Backend Dependencies
```bash
pip install -r backend/requirements.txt
```

### 4. Seed Knowledge Graph (Idempotent)
Populate FalkorDB with synthetic benchmark demonstration scenarios:
```bash
python -m backend.scripts.seed_graph
```
*(Running this script repeatedly uses Cypher `MERGE` and creates zero duplicate records!)*

### 5. Launch the Application
Run the unified launcher:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
Open your browser at:  
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

*(For React frontend development with hot-reload, run `npm run dev` in `frontend/`)*

---

## 🧪 Demonstration Walkthrough (End-to-End)

1. **Open Dashboard**:
   Navigate to `http://127.0.0.1:8000`. Notice the active protection status.
2. **Trigger Synthetic Bank KYC Drill**:
   In the Simulator bar, click **Fake KYC (Cyber Drill)**.
3. **Inspect Alert Modal**:
   Notice the immediate high-risk warning. Click **Investigate Connected Evidence**.
4. **Observe FalkorDB Graph Output**:
   * **Connected Entities**: Identifies lookalike domain `sbi-kyc-verify-portal.in` and claimed organization `State Bank of India`.
   * **Cross-Message Correlation**: FalkorDB reveals **2 historical messages** in the database (`HIST_KYC_VAR_01` and `HIST_KYC_VAR_02`) that direct traffic to the same typosquatted domain.
   * **Threat Report Provenance**: Displays `REP_SYNTH_KYC_01` labeled clearly as `SYNTHETIC_BENCHMARK`.
   * **Grounded Narrative**: The agent explains why the domain and credential-harvesting indicators confirm a recurring campaign rather than a one-off spam message.
   * **Uncertainty Notice**: Explicitly emphasizes that shared infrastructure represents an investigative lead, not automated proof of fraud.

---

## 🛡️ Methodology & Uncertainty Disclosure

* **Investigative Lead, Not Automated Proof**: A shared domain, IP address, or phone number provides relational lead data for security analysts. Legitimate content distribution networks, shared hosting, and shorteners may link benign communications. ScamShield Graph never treats shared indicators as definitive proof of guilt without independent corroboration.
* **Synthetic Data Transparency**: Demonstration indicators and threat reports are strictly labeled with `SYNTHETIC_BENCHMARK` badges to prevent confusion with genuine law enforcement feeds.
* **Graceful Degradation**: If FalkorDB cannot be reached, the system reports an informative HTTP 503 error with exact container startup instructions, rather than silently pretending that graph investigation succeeded.

---

## 🔬 Testing & Verification

Run the full automated test suite (33 comprehensive tests):
```bash
python -m pytest backend/tests/ -v
```

### Verification Checklist:
* [x] **Backend connects to FalkorDB** safely with timeout controls (`backend/services/graph_service.py`)
* [x] **Idempotent seed script** creates expected nodes without duplication (`backend/scripts/seed_graph.py`)
* [x] **Investigation queries** retrieve shared indicators and multi-hop paths (`backend/agents/investigation_agent.py`)
* [x] **Invalid inputs** and missing IDs rejected with HTTP 400 (`backend/api/investigate.py`)
* [x] **Database outages** produce clear HTTP 503 error responses with Docker instructions
* [x] **React UI** displays graph visualization, indicator clusters, and agent explanation (`GraphInvestigationCard.jsx`)
* [x] **Existing ScamShield functionality** (UPI Guard, Attack Chains, Multilingual NLP, SQLite history) fully preserved
* [x] **100% test pass rate** across all 33 tests

---

## 🛠️ Technologies & AI Coding Tools

* **Graph Database**: FalkorDB (`falkordb-py` v1.8.0, Redis protocol v2)
* **Backend Framework**: Python 3.14, FastAPI, Uvicorn, Pydantic v2
* **Relational Persistence**: SQLite (tenant-isolated local storage)
* **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons
* **AI Coding Tools**: Antigravity AI Agent (Google DeepMind), Pair programming for Cypher query design, test generation, and frontend component integration.
