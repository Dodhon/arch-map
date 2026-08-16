# 📚 Research: Architecture Diagram Standards Across Top Tech Companies

> **Document Purpose**: Benchmarking software architecture diagrams and design document practices across Amazon, Google, Microsoft, Stripe, Netflix, and Uber to define the next-generation specification for `arch-map`.

---

## 1. Industry Landscape: Design Docs & Diagram Roles

Top-tier engineering organizations do not rely on ad-hoc "boxes and lines" diagrams. Architecture diagrams serve as load-bearing technical contracts evaluated during rigorous peer reviews, Architecture Review Boards (ARBs), and Principal Engineer bar-raising reviews.

```
+-----------------------------------------------------------------------------------+
|                           Technical Design Document                               |
|                                                                                   |
|  +-------------------------------------+  +------------------------------------+  |
|  | Strategic Narrative / Problem Space |  | Architecture & Data-Flow Diagrams  |  |
|  | - Goals & Non-Goals                 |  | - Level 1: System Context          |  |
|  | - Tenets / Guiding Principles       |  | - Level 2: Component Topology      |  |
|  | - Trade-offs & Alternatives         |  | - Level 3: Request Execution Flow  |  |
|  | - Security, Privacy, Compliance     |  | - Level 4: Failure & Fallback Path |  |
|  +-------------------------------------+  +------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Company-by-Company Standards

### A. Amazon (1-Pagers, 6-Pagers, DTDs & Principal Reviews)
* **The Format**: Narrative prose (no slide decks). 1-pagers for directional validation; 6-pagers (Deep Thinking Documents / DTDs) for major systems. Architecture diagrams live in the **Appendix** or an accompanying **Architecture Decision Record (ADR)**.
* **Core Review Criteria (Marc Brooker & Werner Vogels)**:
  1. **Control Plane vs. Data Plane Separation**: Fast, highly-available request paths (*data plane*) must never depend synchronously on configuration or management paths (*control plane*).
  2. **Failure Domains & Blast Radius**: Clear visualization of Availability Zone (AZ) independence, regional redundancy, and cell-based partitioning.
  3. **Sync vs. Async Decoupling**: Showing where operations block synchronously (HTTP/gRPC) vs. where they decouple via message queues (SQS), streams (Kinesis), or event buses (EventBridge).
  4. **Data Ownership**: Strict prohibition of shared multi-service databases. Each service strictly encapsulates its data store.
  5. **Degraded Operation Modes**: What happens when an external dependency is unavailable or throttled (e.g., fallback caches, circuit breakers, load shedding).

---

### B. Google (Engineering Design Docs & SRE Reviews)
* **The Format**: Standard Google Design Doc structure (`Context` $\rightarrow$ `Goals/Non-Goals` $\rightarrow$ `System Overview` $\rightarrow$ `Detailed Design` $\rightarrow$ `Security/Privacy` $\rightarrow$ `Observability/SRE`).
* **Core Review Criteria**:
  1. **Layered Abstraction**: High-level context $\rightarrow$ component boundaries $\rightarrow$ internal state machines.
  2. **Explicit RPC & Wire Protocols**: Edges must label transport types (e.g., `gRPC / Protobuf`, `Stubby`, `HTTPS / REST`).
  3. **Trust & Security Boundaries**: Clear demarcations of untrusted public networks, Google Front End (GFE) termination, and internal production Borg clusters.
  4. **SLI/SLO Tap Points**: Showing where telemetry, distributed tracing (Dapper), and metrics (Monarch) hook into the serving path.

---

### C. Microsoft & Azure Well-Architected Framework
* **The Format**: Formalized under the Azure Architecture Center design guidelines.
* **Core Diagram Requirements**:
  1. **System Context Diagram**: Workload as a single black box with external actors, data sources/sinks, and perimeter scope.
  2. **High-Level System / Container Diagram**: Macro-structure showing hosting models (PaaS, Serverless, Containers, VMs).
  3. **Data-Flow Diagram (DFD) with STRIDE Trust Boundaries**: Mapping data transformations, classification (Public vs. Confidential), and token issuance/isolation zones.
  4. **Sequence Diagram**: Temporal ordering of events for critical P0 use cases and fault scenarios.

---

### D. Stripe, Netflix, and Uber (RFC & Resilience Culture)
* **Stripe**: Focuses on **idempotency perimeters**, state-machine consistency, and ledger atomicity. Diagrams must identify where idempotency keys are enforced and where distributed locks begin/end.
* **Netflix**: Focuses on **Chaos Resilience**. Diagrams must highlight fallback paths (e.g., "If personalization fails, return cached top-10 list rather than HTTP 500").
* **Uber**: Focuses on **Event Streams & Domain Gateways**. Diagrams strictly separate real-time dispatch RPC paths from Kafka event-driven streaming pipelines.

---

## 3. The 4 Golden Diagram Views

Distilled from the C4 Model (Simon Brown) and Big Tech review standards:

| Level | View Name | Target Audience | Primary Question Answered |
| :--- | :--- | :--- | :--- |
| **Level 1** | **System Context & Trust Boundary** | Leadership, Product, Security | *Who uses this system, and what external dependencies lie outside our control?* |
| **Level 2a** | **Control Plane (Wiring / Factories)** | Architects, SREs | *How is the application instantiated, injected, and configured?* |
| **Level 2b** | **Client Data-Flow Topology (Data Plane)** | Engineers, Reviewers | *How do internal clients and storage services exchange data at runtime?* |
| **Level 3** | **Request Sequence & State Transform** | Developers, On-Call Engineers | *What is the exact execution order, parameter passing, and state write for a request?* |
| **Level 4** | **Failure & Fallback Resilience** | SREs, Security, Principal Reviewers | *What breaks when a dependency times out, and where are fallbacks implemented?* |

---

## 4. Gap Analysis: Benchmarking `arch-map`

| Capability | Big Tech Standard | Current `arch-map` Status | Proposed Next Step |
| :--- | :--- | :--- | :--- |
| **Deterministic Extraction** | Code is source-of-truth; zero drift | ✅ AST analysis + Python stdlib AST | Keep pure standard library |
| **Hierarchical C4 Structure** | L1 $\rightarrow$ L2 $\rightarrow$ L3 | ✅ Implemented (L1 Context, L2 Topology, L3 Sequence) | Refine into 2a (Wiring) and 2b (Data Flow) |
| **Import / Dependency Isolation** | Distinguish internal code from external SDKs | ✅ Groups internal runtimes vs. external packages | Add visual indicators for SDK categories |
| **Environment / Deployment Matrix** | Lift-and-shift inventory of env vars & secrets | ✅ Implemented (Consumed, Declared, Category) | Keep as standard Level 5 view |
| **Client-to-Client Data Flow** | Show data exchange between services (A $\rightarrow$ B $\rightarrow$ C) | ⚠️ Missing: L2 shows `owns`; L3 shows sequence | **Add Level 2b Client Data-Flow Graph** |
| **Storage Semantics** | Distinguish DBs, Object Stores, and Caches | ⚠️ Generic import nodes for all storage | **Use Mermaid cylinders `[()]` and disks `[([])]`** |
| **Sync vs. Async Edges** | Differentiate blocking RPCs from queues/events | ⚠️ All edges use solid arrows (`-->`) | **Use dotted arrows (`-.->`) for async events** |
| **Error Handling / Fallbacks** | Highlight `try/except` and fallback paths | ⚠️ Only happy path is traced | **Annotate `alt / opt` blocks in Level 3** |

---

## 5. Next Steps for `arch-map`

1. **Implement Level 2b (Client Data-Flow Graph)**: Statically trace variable assignments into downstream function calls to draw direct client-to-client data edges.
2. **Add Storage Semantic Shapes**: Automatically assign database cylinders `[(Cosmos / Postgres)]` and object-storage shapes `[([Blob / S3])]` based on SDK classification.
3. **Separate Control Plane from Data Plane**: Distinguish factory initialization (`create_app`) from runtime execution (`chat()`).
4. **Extract Fallback Branches**: Detect `try/except` handlers and render error paths in sequence diagrams.
