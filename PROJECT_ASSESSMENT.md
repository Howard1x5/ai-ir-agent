# RAG-Based Malware Analysis Agent: Project Assessment

**Author:** Clint Howard
**Date:** February 2026
**Project:** AI-Powered Incident Response Agent
**Status:** Completed - Lessons Learned

---

## Executive Summary

I built an autonomous malware analysis agent using Retrieval-Augmented Generation (RAG) to automate the analysis of suspicious files on a FLARE VM. The goal was to replicate the workflow of a human malware analyst using AI.

**The result:** The RAG agent significantly underperformed compared to Claude Code's direct analysis approach. This project provided valuable insights into when RAG is (and isn't) the appropriate tool for security automation.

**Key Takeaway:** RAG is excellent for knowledge retrieval but insufficient for complex reasoning tasks. Malware analysis requires synthesis, adaptive decision-making, and domain expertise - capabilities that emerge from strong reasoning models, not retrieval systems.

---

## What Was Built

### Architecture

```
┌─────────────────────────────────────────────────────┐
│              RAG Agent (Orchestrator)               │
│  - Receives sample path                             │
│  - Retrieves context from ChromaDB                  │
│  - Calls Claude API for next action                 │
│  - Executes command via SSH                         │
│  - Loops until complete or max steps                │
└─────────────────────┬───────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
┌───────────┐  ┌───────────┐  ┌───────────┐
│ RAG System│  │SSH Executor│  │Detonation │
│ (ChromaDB)│  │ (Paramiko)│  │ Guard     │
└───────────┘  └───────────┘  └───────────┘
```

### Components

1. **RAG System**
   - Vector database: ChromaDB
   - Embeddings: sentence-transformers
   - Corpus: FLARE VM tool docs, analysis procedures, MITRE ATT&CK

2. **SSH Executor**
   - Remote command execution on FLARE VM
   - Jump host through Proxmox
   - Output capture and logging

3. **Detonation Guard**
   - Safety controls to prevent accidental malware execution
   - Path validation
   - Command whitelisting

4. **Claude API Integration**
   - Model: claude-sonnet-4-20250514
   - Purpose: Generate next analysis action based on RAG context
   - Loop: Continue until analysis complete or 25 steps max

### RAG Corpus Contents

- FLARE VM tool documentation (strings, FLOSS, sigcheck, etc.)
- Malware analysis procedure guides
- MITRE ATT&CK technique references
- Tool usage examples

**GitHub Repository:** https://github.com/Howard1x5/ai-ir-agent

---

## Testing Methodology

### Test Sample

**File:** AsyncRAT/VenomRAT variant
**SHA-256:** `06417db53e9b090c7a07192dbb6203ce15c832c0928d73ebbc9c8ebff05320ff`
**Source:** MalwareBazaar
**Type:** .NET PE32 executable
**Known Family:** VenomRAT 6.X

### Test Approach

I analyzed the same sample using two methods:

**Method 1: RAG Agent (Autonomous)**
- Agent decided which tools to run
- Retrieved context from RAG system before each decision
- Executed commands via SSH
- Generated JSON report

**Method 2: Claude Code (Direct)**
- Claude Code performed systematic analysis via SSH
- Used domain knowledge and reasoning
- Applied established malware analysis methodology
- Generated professional IR report

---

## Results: Side-by-Side Comparison

### High-Level Outcomes

| Metric | RAG Agent | Claude Code Direct |
|--------|-----------|-------------------|
| **Analysis Time** | 25 steps, ~17 minutes | Systematic, ~10 minutes |
| **Malware Family** | Not identified | VenomRAT 6.X |
| **Verdict** | "No specific findings" | MALICIOUS - 95% confidence |
| **MITRE Techniques** | 0 mapped | 15 techniques mapped |
| **Actionable IOCs** | False positives | Hashes, behaviors, config |
| **Report Quality** | Minimal context | Professional IR report |

### Detailed Comparison

#### 1. Malware Family Identification

**RAG Agent:**
```json
{
  "malware_family": "Unknown",
  "analysis_complete": true,
  "findings": "No specific findings recorded"
}
```
- Failed to identify malware family despite running DIE (Detect It Easy)
- Did not recognize "Stub.exe" as AsyncRAT/VenomRAT indicator
- Listed tools that could identify family but didn't run them effectively

**Claude Code:**
```markdown
**Malware Family:** VenomRAT 6.X / AsyncRAT variant
**Evidence:**
- Detect It Easy signature match: "Malware: VenomRAT(6.X)"
- Original filename: Stub.exe (default AsyncRAT builder output)
- Class names: Anti_Analysis, ClientSocket, KeepAlivePacket
```
- Immediately identified family using DIE
- Corroborated with multiple indicators
- Understood significance of "Stub.exe" filename

#### 2. Anti-Analysis Techniques

**RAG Agent:**
```
Found strings: "VIRTUAL", "vmware", "VirtualBox"
Decoded Base64: vDEMTCqc9WmtW0baiLqj8kE5dGOdwHM8
```
- Found anti-VM strings but didn't explain significance
- Decoded Base64 but didn't identify it as encryption key
- No systematic enumeration of evasion techniques

**Claude Code:**
```markdown
**Anti-Analysis Suite (5 techniques identified):**
1. Sandbox Detection (SbieDll.dll check)
2. Debugger Detection (CheckRemoteDebuggerPresent)
3. VM Detection (VMware, VirtualBox, Hyper-V strings)
4. Small Disk Detection (sandbox environment detection)
5. String Obfuscation (reversal: "noisreVtnerruC")

Each mapped to MITRE ATT&CK techniques.
```
- Systematically identified all evasion techniques
- Explained purpose and method for each
- Mapped to MITRE framework

#### 3. MITRE ATT&CK Mapping

**RAG Agent:**
```
MITRE techniques: []
```
- Zero techniques mapped despite having MITRE data in RAG corpus
- Retrieved technique definitions but couldn't connect behaviors to techniques
- No synthesis between observed behaviors and framework

**Claude Code:**
```markdown
15 Techniques Mapped:
- T1497: Virtualization/Sandbox Evasion
- T1622: Debugger Evasion
- T1053.005: Scheduled Task
- T1547.001: Registry Run Keys
- T1071: Application Layer Protocol
- T1573: Encrypted Channel
[...9 more...]
```
- Comprehensive technique mapping
- Evidence provided for each mapping
- Organized by tactic (Defense Evasion, Persistence, C2)

#### 4. Configuration Extraction

**RAG Agent:**
```
Base64 decoded: vDEMTCqc9WmtW0baiLqj8kE5dGOdwHM8
```
- Successfully decoded Base64 string
- Did not identify its purpose (AES encryption key)
- Did not attempt to decrypt configuration blobs

**Claude Code:**
```markdown
**Extracted AES-256 Encryption Key:**
vDEMTCqc9WmtW0baiLqj8kE5dGOdwHM8

**Purpose:** Decrypts embedded configuration containing:
- C2 server addresses (Hosts)
- C2 ports (Ports)
- Mutex name (MTX)
- Campaign group identifier

**Encrypted Config Blobs:** [4 identified]
```
- Identified decoded string as AES key
- Documented encryption algorithm (AES-256-CBC)
- Explained what can be decrypted with this key
- Provided context for dynamic analysis

#### 5. Persistence Mechanisms

**RAG Agent:**
```
Found command: schtasks /create /f /sc onlogon
```
- Partial command found in strings
- No explanation of persistence mechanism
- No registry run key identification

**Claude Code:**
```markdown
**Primary Persistence: Scheduled Task**
Command: schtasks /create /f /sc onlogon /rl highest /tn "<n>" /tr "<path>"
Trigger: User logon
Privilege: Highest available
MITRE: T1053.005

**Secondary Persistence: Registry Run Key**
Path: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Method: String reversal obfuscation
MITRE: T1547.001
```
- Complete persistence documentation
- Explained privilege escalation (/rl highest)
- Identified secondary mechanism
- MITRE mapping for both

#### 6. Tools Effectively Used

**RAG Agent:**
- certutil (basic hash calculation)
- strings (partial results)
- FLOSS (timeout/incomplete)
- DIE (ran but ignored results)
- CAPA (not attempted)
- sigcheck (not attempted)
- de4dot (not attempted)

**Claude Code:**
- certutil (hashes)
- file (type identification)
- sigcheck (PE metadata)
- DIE (family identification)
- de4dot (obfuscation detection)
- strings (comprehensive extraction)
- CAPA (capability analysis)
- PowerShell (Base64 decoding)

#### 7. IOC Extraction

**RAG Agent:**
```json
{
  "iocs": {
    "domains": [
      "System.Security.Cryptography",
      "Microsoft.VisualBasic.CompilerServices",
      "System.Net.Sockets"
    ]
  }
}
```
- Misidentified .NET namespaces as domains (false positives)
- No actual network IOCs extracted
- No behavioral indicators documented

**Claude Code:**
```markdown
**File IOCs:**
- SHA-256: 06417db53e9b090c7a07192dbb6203ce15c832c0928d73ebbc9c8ebff05320ff
- Original name: Stub.exe
- Install path: %Temp%\aha.exe

**Behavioral IOCs:**
- Scheduled task created at logon with /rl highest
- Registry key: HKCU\...\CurrentVersion\Run
- WMI query: Select * from AntivirusProduct
- DLL check: SbieDll.dll (Sandboxie detection)

**Config Artifacts:**
- AES Key: vDEMTCqc9WmtW0baiLqj8kE5dGOdwHM8
- Mutex: MTX (dynamic)
```
- Accurate IOC extraction
- No false positives
- Behavioral indicators documented
- Ready for SIEM ingestion

---

## Analysis: Why RAG Underperformed

### 1. No Synthesis Capability

**RAG's limitation:** Retrieves relevant documents but can't reason across them.

**Example:**
- RAG found: "Stub.exe is common in RATs"
- RAG found: "VenomRAT uses AES encryption"
- RAG found: "Anti-VM strings indicate evasion"
- **But couldn't connect:** "Stub.exe + AES key + anti-VM = VenomRAT"

**Claude Code's advantage:** Synthesized multiple indicators into confident verdict.

### 2. Random Tool Selection

**RAG's approach:**
```
Step 1: Run strings
Step 2: Run FLOSS
Step 3: Try pestudio (timeout)
Step 4: Run strings again
[No systematic progression]
```

**Claude Code's approach:**
```
1. File type identification (file, sigcheck)
2. Family identification (DIE)
3. Capability analysis (CAPA)
4. Static analysis (strings, deobfuscation)
5. Synthesis into report
[Systematic methodology]
```

### 3. No Domain Understanding

**RAG failed to recognize:**
- "Stub.exe" = AsyncRAT/VenomRAT builder default output
- Reversed strings = common obfuscation technique
- Base64 blob = likely encrypted configuration
- schtasks + /rl highest = privilege escalation persistence

**Claude Code understood context** without needing explicit documentation for each pattern.

### 4. Weak Verdict Generation

**RAG's output:**
```json
{
  "verdict": "Analysis complete",
  "confidence": null,
  "classification": "Unknown"
}
```

**Claude Code's output:**
```markdown
**Classification:** MALICIOUS
**Confidence:** HIGH (95%)
**Reasoning:**
- Signature match (VenomRAT 6.X)
- Encrypted C2 configuration
- Anti-analysis suite
- Persistence mechanisms
- Unsigned executable with RAT capabilities
```

**Key difference:** Claude Code can say "this is malicious BECAUSE..." while RAG could only list facts.

---

## When RAG IS Valuable

Despite the underwhelming performance in this test, RAG has specific, valuable use cases in security:

### Use Case 1: Knowledge Lookup
**Question:** "What MITRE ATT&CK technique matches registry run key persistence?"

**RAG excels here:**
- Fast retrieval: < 1 second
- Accurate: Returns T1547.001 with description
- Cheaper than reasoning: Embedding search vs. LLM call

**Example RAG response:**
```
Technique: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
Description: Adversaries may achieve persistence by adding programs to startup folders or registry run keys...
Detection: Monitor Registry for changes to run keys...
```

### Use Case 2: Historical Analysis Comparison
**Question:** "Have we analyzed other AsyncRAT samples? What did we find?"

**RAG excels with corpus:**
- Semantic search across past analyses
- Find similar samples by behavior
- Identify evolution/variants

**Example RAG response:**
```
Found 3 previous AsyncRAT analyses:
- 2024-11-15: AsyncRAT with registry-only persistence
- 2024-08-20: VenomRAT 5.X with different AES key
- 2023-12-10: AsyncRAT with SMB spreading

Key differences: This sample uses BOTH schtasks and registry (unusual)
```

**Limitation:** Requires corpus of past analyses (I only had 3 blog posts, not 50+ reports)

### Use Case 3: Tool Usage Guidance
**Question:** "How do I configure CAPA to analyze .NET malware?"

**RAG excels:**
- Retrieve tool documentation
- Provide specific flags and examples
- Show expected output format

**Example RAG response:**
```
CAPA for .NET Analysis:
Command: capa.exe -v sample.exe
Flags: -v (verbose), --format json (structured output)
Note: CAPA auto-detects .NET and applies appropriate rules
```

### Use Case 4: Threat Intelligence Lookup
**Question:** "What campaigns currently use AsyncRAT?"

**RAG excels with live feeds:**
- Query threat intel databases
- Return campaign associations
- Link to IOCs and attribution

**Example RAG response:**
```
Current AsyncRAT Campaigns:
- Operation SilentRaven (targeting financial sector)
- APT-C-36 (healthcare targeting)
- FIN7 (AsyncRAT as secondary payload)

Shared IOCs: [C2 infrastructure overlap]
```

**Limitation:** Requires integration with threat intel feeds (I didn't have this)

---

## The Right Architecture: RAG as a Tool, Not the Brain

### What I Built (Doesn't Scale)

```
RAG Agent (orchestrator)
  ├─ Retrieves context from ChromaDB
  ├─ Asks Claude: "What should I do next?"
  ├─ Executes command
  └─ Loops (limited reasoning, poor synthesis)
```

**Problem:** RAG is making decisions it can't reason through.

### What Works (Hybrid Approach)

```
Claude Code (orchestrator)
  ├─ Applies malware analysis methodology
  ├─ Queries RAG when needed:
  │   ├─ "What's the MITRE technique for this?"
  │   ├─ "Have we seen this before?"
  │   └─ "How do I use tool X?"
  ├─ Synthesizes findings across all sources
  └─ Generates comprehensive verdict
```

**Why it works:** Strong reasoning (Claude Code) + specialized retrieval (RAG) + tool execution (SSH)

---

## Lessons Learned

### 1. RAG is a Library, Not an Analyst

**Insight:** RAG excels at "looking things up" but can't replace reasoning.

**Analogy:** A library has all the books, but you still need a smart person to read them and draw conclusions.

**Application:** Use RAG for retrieval, use Claude/GPT for analysis.

### 2. Corpus Quality > Corpus Size

**Mistake:** I indexed general tool documentation.

**Better approach:** Index specific, high-value content:
- Your organization's past analyses
- Custom playbooks and procedures
- Threat intel on actors targeting YOUR environment

**Learning:** 10 highly relevant documents > 100 generic ones.

### 3. Test with Real Samples, Not Toy Examples

**Mistake:** I assumed RAG would work based on EICAR test.

**Reality:** Real malware (AsyncRAT) exposed synthesis gaps.

**Learning:** Always validate with production-like scenarios.

### 4. Multi-Tool Workflows Need Strong Reasoning

**Observation:** Malware analysis requires:
- Knowing which tools to run in which order
- Interpreting results in context
- Connecting findings across tools
- Making judgment calls

**Conclusion:** This is reasoning-heavy, not retrieval-heavy work.

### 5. Know When to Use Each Tool

| Task Type | Best Tool | Why |
|-----------|-----------|-----|
| Knowledge lookup | RAG | Fast, cheap, accurate retrieval |
| Complex analysis | Claude Code | Reasoning, synthesis, adaptation |
| Historical comparison | RAG | Semantic search across corpus |
| Verdict generation | Claude Code | Requires judgment and context |
| Tool guidance | RAG | Documentation retrieval |
| Adaptive investigation | Claude Code | Decision-making under uncertainty |

---

## What This Means for AI in Security

### The Hype vs. Reality

**Hype:** "RAG agents will automate everything!"

**Reality:** RAG is one component in an automation pipeline, not a complete solution.

### Successful AI Security Patterns

**Pattern 1: AI-Assisted (Works Today)**
- Human analyst drives investigation
- AI provides knowledge lookup (RAG)
- AI suggests next steps (Claude)
- Human makes final decisions

**Pattern 2: Hybrid Automation (Near Future)**
- AI orchestrator (Claude Code)
- RAG for specialized knowledge
- Computer use for GUI tools
- Human oversight for critical decisions

**Pattern 3: Full Autonomy (Distant Future)**
- Still needs strong reasoning at the core
- RAG is one of many tools
- Extensive safety controls required

### Where RAG Adds Real Value in IR

1. **Incident triage**: "Show me similar past incidents"
2. **Playbook adherence**: "What's our procedure for ransomware?"
3. **Threat intel lookup**: "What do we know about this IOC?"
4. **Knowledge base**: "How do I use this tool?"
5. **Historical context**: "How have we seen this actor operate?"

**Common theme:** All are retrieval tasks, not reasoning tasks.

---

## Conclusion

### What I Built

A functional RAG-based malware analysis agent with:
- Working SSH automation
- Solid safety controls (detonation guards)
- Clean architecture (modular, testable)
- Integration with Claude API

### What I Learned

RAG agents are not a silver bullet for complex security automation. They excel at specific retrieval tasks but require strong reasoning models (like Claude Code) for synthesis and decision-making.

**The key insight:** Use RAG as a specialized tool within a reasoning-driven architecture, not as the orchestrator itself.

### What I'd Do Differently

**If building again:**
1. Start with Claude Code as orchestrator
2. Add RAG as a knowledge lookup tool (MCP server)
3. Build historical analysis database as I accumulate samples
4. Integrate threat intel feeds for real-time IOC context
5. Use computer use for GUI tool interaction

**But first:** Accumulate 20-50 analyses to make RAG corpus valuable.

### Value of This Project

While the RAG agent underperformed, this project delivered value:
- **Hands-on learning** about AI agent architectures
- **Real testing** with production malware samples
- **Honest assessment** of RAG capabilities and limitations
- **Foundation** for future automation (SSH executor, safety controls)
- **Clear direction** for AI-assisted IR (hybrid approach)

### Final Thought

The best engineering projects are the ones that teach you what NOT to do. This project proved that RAG alone isn't sufficient for complex malware analysis - and that's a valuable lesson worth documenting.

**Building things, testing them, and learning from the results is how we improve. This is that process in action.**

---

## Appendix: Evidence

### RAG Agent Output (Sanitized)
```json
{
  "analysis_id": "AsyncRAT_sample_20260203",
  "status": "complete",
  "steps_executed": 25,
  "duration_minutes": 17,
  "findings": {
    "malware_family": "Unknown",
    "verdict": "No specific findings recorded",
    "mitre_techniques": [],
    "iocs": {
      "file_hashes": ["06417db..."],
      "domains": [
        "System.Security.Cryptography",
        "Microsoft.VisualBasic.CompilerServices"
      ]
    }
  },
  "tools_used": ["certutil", "strings", "floss"],
  "errors": ["pestudio timeout", "dnSpy not responsive"]
}
```

### Claude Code Output (Sanitized)
See full report: [AsyncRAT_ClaudeCode_Analysis.md](reports/AsyncRAT_ClaudeCode_Analysis.md)

**Summary:**
- Malware Family: VenomRAT 6.X
- Confidence: 95%
- MITRE Techniques: 15
- IOCs: Comprehensive
- Report: Professional IR quality

---

**Project Repository:** https://github.com/Howard1x5/ai-ir-agent
**Author:** Clint Howard
**Contact:** [GitHub](https://github.com/Howard1x5)

---

*This assessment reflects real testing and honest evaluation. Building things that don't work as expected is part of the learning process - the key is documenting what you learned so others (and future you) can benefit.*
