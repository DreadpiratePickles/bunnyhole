# Module 7: The Link Sleuth — Dead-End Breaking, Lateral Pivoting & Interconnection Synthesis

> **Purpose:** Collecting data is only half of an investigation. Real breakthroughs happen when an investigator asks:
> 1. *"This lead hit a wall (a dead end)—how do I flank around it using an orthogonal side-channel?"*
> 2. *"How are Person A, Shell Company B, Domain C, and Wallet D actually interconnected across 4 degrees of separation?"*
> 3. *"Which two nodes in my graph aren't directly connected yet, but mathematically MUST know each other because of their shared rare intermediaries?"*

To solve this, Bunnyhole introduces a dedicated **6th Specialist Agent**: **🔗 The Pathfinder / Link Sleuth (`LinkSleuthAgent`)**.

---

## 1. Anatomy of an Investigative Dead End & The "Lateral Bypass Matrix"

In amateur OSINT, when a lookup returns `"WHOIS Redacted for Privacy"` or `"Delaware LLC — Registered Agent Only"`, the investigation stops. Professional intelligence officers treat every dead end as a **Classification Problem**: once you classify *what kind* of wall you hit, there is a deterministic **Lateral Bypass Playbook** that goes around the wall through a different domain.

```mermaid
flowchart TD
    DeadEnd["🧱 Dead-End Node Detected\n(Degree == 1 Leaf Node or Redacted Record)"] --> Classify{"Classify Wall Type"}
    
    Classify -->|Type 1: Opaque Shell LLC\n(DE / WY / BVI / Cayman)| Bypass1["🏛️ Lateral Bypass 1: Indirect Regulatory Footprints\n• SEC Form D (Private Raise Signers & Phone)\n• GLEIF Parent Exception Codes\n• CourtListener Dockets (Who Sued Them?)\n• USAspending / FEC Employer Mentions"]
    
    Classify -->|Type 2: Redacted Domain\n(Cloudflare + Privacy WHOIS)| Bypass2["🕵️ Lateral Bypass 2: Historical & Asset Side-Channels\n• Wayback Earliest Snapshot (Pre-Cloudflare / Pre-GDPR WHOIS)\n• crt.sh Multi-Domain SAN Siblings\n• Favicon mmh3 & GA/GTM/AdSense Tag Pivots\n• Exposed .js.map Sourcemap Local File Paths"]
    
    Classify -->|Type 3: Unlabeled Fresh Wallet\n(No ENS / No Direct CEX Label)| Bypass3["⛓️ Lateral Bypass 3: Behavioral & Sibling Clustering\n• Walk Back to Mother Gas Funder -> Enumerate All Sibling Burners\n• Check Outgoing EOA Sweeps -> Find Shared CEX Deposit Address Co-Depositors\n• Decode THORChain / Bridge Calldata Memos"]
    
    Classify -->|Type 4: Ghost Person / Scrubbed Exec\n(No Public Socials)| Bypass4["👤 Lateral Bypass 4: High-Friction Mandatory Disclosures\n• FEC Political Donations (Name + Employer + City/Zip)\n• UK PSC Month/Year of Birth Match\n• Git Commit .patch Raw Author Email\n• HudsonRock Infostealer Telemetry"]

    Bypass1 --> Revived["🔥 Dead End Cracked -> New Cross-Domain Leads Injected!"]
    Bypass2 --> Revived
    Bypass3 --> Revived
    Bypass4 --> Revived
```

### How the Dead-End Breaker Algorithm Works
After every hop of the main domain agents, the **Link Sleuth** scans the `InvestigationGraph` for **Stalled Leaf Nodes**:
$$\text{Stalled}(v) \iff \text{deg}(v) \le 1 \;\land\; \text{hop\_depth}(v) \ge 1 \;\land\; \text{smoke\_score}(v) \ge 35$$

For each stalled node, the Link Sleuth generates **Orthogonal Cross-Domain Queries**:
1. **Cross-Entity Co-Occurrence Query (`"Entity A" AND "Entity B"`):**
   * If `Node A` (e.g., the root target company or founder) and `Node B` (a stalled leaf subsidiary, lawyer, counterparty, or domain) appear in the graph without clear context, the Link Sleuth runs a targeted **Joint Co-Occurrence Search** across News RSS, Court Dockets, and SEC filings for `"Node A" "Node B"` to uncover the exact contract, lawsuit, or transaction that binds them.
2. **Attribute Decomposition ("The Sub-Selector Split"):**
   * If a full company name `"Aetherius Global Holdings LLC"` hits a dead end, the Link Sleuth strips corporate suffixes (`Holdings`, `Global`, `LLC`, `Ltd`, `Labs`, `Protocol`, `Foundation`) to extract the **Unique Stem Token (`"aetherius"`)** and pivots that stem across:
     * GitHub Organizations & Repos (`github.com/aetherius*`)
     * Certificate Transparency (`%.aetherius.%`)
     * DeFiLlama / DexScreener token symbols

---

## 2. Mathematical Link Analysis: How Things Interconnect

The Link Sleuth runs **4 graph-theoretic algorithms** over the Universal Investigation Graph to reveal hidden structures that human eyes miss in a messy web of nodes:

### 2.1 Multi-Domain Pathfinding ("Six Degrees of Bunnyhole")
Given any two entities $u$ and $v$ in the investigation (or automatically between the top high-smoke anomalies), the Link Sleuth computes **All Simple Paths** up to length $k \le 6$ in the undirected projection of the graph, scoring each path by its **Chain Credibility Product**:

$$\text{PathScore}(P) = \left(\prod_{e \in P} \text{confidence}(e)\right)^{\frac{1}{|P|}} \times \left(1 + 0.15 \cdot |\text{UniqueDomains}(P)|\right)$$

* **Why Cross-Domain Paths Score Higher:** A path that crosses from **Fiat (`SEC Filing`) $\rightarrow$ Identity (`Executive Name`) $\rightarrow$ OSINT (`GitHub Commit Email`) $\rightarrow$ On-Chain (`Deployer Wallet`)** is a **Cross-Domain Bridge Chain**—the holy grail of investigative attribution.

### 2.2 Triadic Closure & "Missing Link" Prediction (Adamic-Adar & Resource Allocation)
Suppose `Person X` and `Organization Y` have no direct edge between them in our graph yet, but both are connected to a set of common neighbors $\Gamma(X) \cap \Gamma(Y)$.
* Should we suspect a hidden link between `X` and `Y`?
* **It depends on the rarity of the shared neighbor!**
  * If `X` and `Y` both connect to `Delaware` or `Cloudflare` (where $|\Gamma(z)| = 10,000$), that means nothing.
  * If `X` and `Y` both connect to a rare boutique accounting firm, a specific Google Analytics `G-XXXX` tag, or a single CEX deposit address (where $|\Gamma(z)| = 2$), that is a **Smoking Gun**.
* The Link Sleuth computes the **Adamic-Adar Similarity Index** for all non-adjacent node pairs $(x, y)$ at distance 2:
  $$\text{AA}(x, y) = \sum_{z \in \Gamma_s(x) \cap \Gamma_s(y)} \frac{1}{\ln(\max(2, \text{deg}(z)))}$$
  *(where $\Gamma_s$ excludes nodes flagged as `MASS_REGISTERED_AGENT_ADDRESS` or `SHARED_ANYCAST_CDN_IP`)*.
* Any pair $(x, y)$ with high $\text{AA}(x, y)$ is surfaced as a **Predicted Hidden Connection** and queued for a direct co-occurrence verification sweep!

### 2.3 Cut-Out, Broker & "Keystone Entity" Identification
Criminal and corporate networks rely on **Keystone Intermediaries**:
* **Corporate Cut-Out:** A single lawyer, company secretary, or family office accountant who sits on the filings of 6 "unrelated" companies.
* **Infrastructure Cut-Out:** A single devOps contractor or shared staging server whose TLS certificate or `.js.map` file links 3 "unrelated" websites.
* **Financial/On-Chain Cut-Out:** A single OTC broker wallet or CEX deposit sweep address that receives funds from multiple exploit/insider clusters.

The Link Sleuth combines:
1. **Betweenness Centrality** $C_B(v)$ (how many shortest paths across the investigation pass through $v$)
2. **Domain Entropy** $H_{\text{dom}}(v) = -\sum_{d \in \text{Domains}} p_d \ln p_d$ (whether $v$'s neighbors span multiple investigative domains: Journalism, Fiat, OSINT, On-Chain, Physical)
3. **Articulation Point Status** (removing $v$ splits the connected component in two).

Nodes scoring high on both $C_B(v)$ and $H_{\text{dom}}(v)$ are crowned **🔗 Keystone Connectors / Cut-Out Brokers** and highlighted with a dedicated badge in both the CLI dossier and the interactive Web Graph UI!

### 2.4 Louvain / Modularity Community Clustering ("Syndicate Mapping")
When an investigation grows to 30–150+ nodes, the Link Sleuth partitions the graph into **Operational Cells / Communities** using greedy modularity maximization (`nx.community.greedy_modularity_communities`), automatically labeling each cluster by its dominant entities and showing the exact **Inter-Cluster Bridge Edges** that connect one cell to another.

---

## 3. How the Link Sleuth Operates in Both CLI & Web UI

1. **Automatic Post-Hop Pass:** At the end of every investigation hop, `LinkSleuthAgent` runs:
   * **Step 1 (Dead-End Diagnosis & Revival):** Finds stalled leaf nodes, classifies the wall type, and injects lateral bypass leads (stem pivots, co-occurrence searches, sibling wallet sweeps).
   * **Step 2 (Missing Link Prediction):** Runs Adamic-Adar triadic closure to infer hidden connections between 2-hop neighbors and runs targeted verification queries (`"Entity A" AND "Entity B"`).
   * **Step 3 (Path & Keystone Synthesis):** Computes all cross-domain paths, keystone brokers, and modularity communities.
2. **Interactive "How Do These Link?" Mode (Web UI & CLI):**
   * Select any two nodes on the canvas (or run `bunnyhole link <entity_A> <entity_B>`) and the Link Sleuth actively hunts from both ends simultaneously (**Bidirectional Meet-in-the-Middle Search**) until their graphs intersect!
