# 🏆 ScamShield Graph — WeMakeDevs Graph Hacks 2026 Submission Deliverable

* **Hackathon**: Graph Hacks 2026 by WeMakeDevs, Powered by FalkorDB
* **Selected Track**: Track 1 — Agents That Act on Connected Data
* **Repository**: [ScamShield-v2](https://github.com/venkatasaiaitha-dotcom/ScamShield-v2)
* **Target Submission Deadline**: October 18, 2026 at 11:59 PM IST
* **Current Status**: Complete, Verified & Submission-Ready

---

## 1. Project Description

**ScamShield Graph** is an explainable, graph-powered cyber defense and scam investigation agent. While traditional security tools evaluate incoming text and links in isolation, adversaries operate across distributed networks—routinely reusing lookalike domains, virtual phone numbers, UPI payment handles, and deceptive phrasing across multiple targets.

ScamShield Graph transforms proactive incoming message inspection into an active graph investigation. When a message arrives across connected channels (SMS, Gmail, Webhook), ScamShield normalizes and analyzes the text, tokenizes suspicious links, and ingests the entities into a dedicated **FalkorDB knowledge graph (`scamshield`)**. 

An autonomous **Investigation Agent** executes parameterized Cypher queries through specialized graph tools (`find_shared_indicators`, `trace_connected_evidence`, `get_evidence_summary`) to determine whether the message shares indicators with known syndicates, historical attack variants, or threat intelligence advisories. The agent synthesizes a transparent, evidence-grounded report with interactive graph visualization, distinguishing confirmed facts, synthetic demonstration data, and uncertainty limitations.

---

## 2. Architecture & Data Flow

```
+───────────────────────────────────────────────────────────────────────────+
|                             REACT FRONTEND                                |
|  - Real-Time Protection Dashboard & Inbound Simulator                     |
|  - Threat Alert Modal with "Investigate Connected Evidence" Action        |
|  - Interactive Entity-Relationship Graph Visualizer                       |
+───────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼ (HTTP / Authenticated WebSocket)
+───────────────────────────────────────────────────────────────────────────+
|                            FASTAPI BACKEND                                |
|  - Message Ingestion & Multi-Vector Analyzer                              |
|  - SSRF URL Tokenizer, UPI Payment Guard & Code-Mixed NLP Heuristics      |
|  - Tenant-Isolated Relational Storage (SQLite)                            |
+───────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+───────────────────────────────────────────────────────────────────────────+
|                  FALKORDB GRAPH SERVICE ('scamshield')                    |
|  - Schema Indices: :Message(id), :Domain(name), :URL(url), :Phone(...)   |
|  - Idempotent Ingestion: Cypher MERGE on Nodes and Relationships         |
+───────────────────────────────────────────────────────────────────────────+
                                     ▲
                                     │ Parameterized Cypher Queries
+───────────────────────────────────────────────────────────────────────────+
|                     AUTONOMOUS INVESTIGATION AGENT                        |
|  - Tool 1: find_shared_indicators(message_id)                             |
|  - Tool 2: trace_connected_evidence(message_id)                           |
|  - Tool 3: get_evidence_summary(message_id)                               |
|  - Grounded Evidence Synthesizer & Uncertainty Disclosure Engine          |
+───────────────────────────────────────────────────────────────────────────+
```

---

## 3. FalkorDB Role & Connected-Data Justification

### Why a Graph Database?
Relational databases store tables; relational joins across multiple hops (e.g. Message ➔ URL ➔ Domain ➔ Historical Messages ➔ Advisory Reports) require expensive recursive multi-table JOINs that degrade at scale. Vector databases only measure semantic proximity; they cannot determine exact shared infrastructure.

### How FalkorDB Solves This:
1. **Microsecond Graph Traversal**: FalkorDB’s C-based GraphBLAS matrix engine enables traversal of multi-hop connected indicators in sub-millisecond query time.
2. **Adversarial Syndicate Unmasking**: Cypher pattern matching uncovers shared lookalike domains (e.g., `sbi-kyc-verify-portal.in`) and recruiter numbers (e.g., `+91-98765-43210`) across seemingly unrelated messages.
3. **Transparent Evidence Provenance**: Traces paths from a live incoming message directly to synthetic or real threat intelligence advisories, providing concrete evidence rather than black-box AI scores.

---

## 4. Track 1 Alignment & Evaluation Criteria

| Hackathon Criterion | ScamShield Graph Implementation |
|---|---|
| **Meaningful Graph Use** | FalkorDB executes actual Cypher graph queries (`MATCH ...-[r]->...`) to find shared domains, phone numbers, and threat reports. Graph is not a superficial visualizer. |
| **Agent Autonomy & Tools** | `InvestigationAgent` coordinates discrete tools (`tool_find_shared_indicators`, `tool_trace_connected_evidence`) and analyzes graph query output to produce grounded explanations. |
| **Idempotency & Data Safety** | All seeding and ingestion queries use Cypher `MERGE`. Seeding repeatedly creates zero duplicate nodes or relationships. |
| **Error Handling & Resilience** | When FalkorDB is offline, API returns HTTP 503 with exact `docker run` commands; does not silently pretend queries succeeded. |
| **Ethical AI & Uncertainty** | Discloses that a shared indicator is an investigative lead, not conclusive proof of guilt. Explicitly labels synthetic demonstration data. |

---

## 5. AI Tool & Technology Disclosure

* **Graph Database**: FalkorDB (`falkordb-py` v1.8.0, Redis protocol v2)
* **Backend Framework**: Python 3.14, FastAPI, Uvicorn, Pydantic v2
* **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons
* **AI Assistance**: Antigravity AI Agent (Google DeepMind) utilized for architectural refactoring, Cypher query parameterization, test generation, and documentation drafting. All code tested and verified locally.
