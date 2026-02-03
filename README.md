# AI-Powered Incident Response Agent

> **Project Status:** Completed with valuable lessons learned
>
> This project successfully demonstrated the limitations of RAG-only approaches for complex malware analysis. **[Jump to Assessment](#project-assessment)** or read the **[Full Analysis](PROJECT_ASSESSMENT.md)** to see what I learned about when RAG is (and isn't) the right tool.

---

## Overview

An AI-powered Incident Response and Malware Analysis agent that uses RAG (Retrieval-Augmented Generation) to provide context-aware analysis capabilities.

This agent combines:
- **Claude API** for intelligent analysis and decision-making
- **RAG System** with malware analysis procedures and techniques
- **SSH Execution** to run commands on isolated analysis VMs
- **Automated Workflow** for systematic malware triage

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AI IR Agent                          │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │ RAG System  │───▶│  Claude API  │───▶│    SSH    │  │
│  │ (Knowledge) │    │ (Reasoning)  │    │ Executor  │  │
│  └─────────────┘    └──────────────┘    └───────────┘  │
│         │                  │                  │        │
│         ▼                  ▼                  ▼        │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │  Procedures │    │   Analysis   │    │ FLARE VM  │  │
│  │  & Guides   │    │   Reports    │    │ (Isolated)│  │
│  └─────────────┘    └──────────────┘    └───────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Features

- **Automated Triage**: Hashes, file type identification, strings extraction
- **RAG-Enhanced Analysis**: Retrieves relevant procedures based on sample characteristics
- **VM Execution**: Safely executes analysis commands on isolated FLARE VM
- **IOC Extraction**: Automatically extracts IPs, domains, hashes, file paths
- **Report Generation**: JSON reports with findings and MITRE ATT&CK mapping

## Requirements

- Python 3.10+
- Anthropic API key
- FLARE VM (or similar Windows analysis VM) accessible via SSH
- Proxmox or similar hypervisor (optional, for jump host setup)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-ir-agent.git
cd ai-ir-agent

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API key and VM details
```

## Configuration

Edit `.env` with your settings:

```bash
# Required
ANTHROPIC_API_KEY=your_api_key_here

# FLARE VM SSH (adjust for your setup)
FLARE_VM_HOST=192.168.1.100
FLARE_VM_USER=analyst
FLARE_VM_PASSWORD=your_password
FLARE_VM_JUMP_HOST=192.168.1.1  # Optional jump host
FLARE_VM_JUMP_USER=root
```

## Usage

### Test Connection
```bash
python analyze.py --test
```

### Analyze a Sample
```bash
# Basic usage
python analyze.py "C:\Users\analyst\Desktop\sample.exe"

# With custom name
python analyze.py "C:\path\to\sample.bin" "suspicious_dropper"

# Limit analysis steps
python analyze.py "C:\path\to\sample.exe" --max-steps 10
```

## RAG Corpus

The agent includes pre-built procedures for:
- Initial malware triage
- PowerShell malware analysis
- VBScript deobfuscation
- PE executable analysis
- Network IOC extraction
- Procmon analysis
- x64dbg debugging
- CyberChef recipes
- YARA rule writing

Add your own procedures by placing JSON files in `corpus/procedures/`.

## Project Structure

```
ai-ir-agent/
├── src/
│   ├── core/
│   │   └── agent.py          # Main agent orchestrator
│   ├── rag/
│   │   ├── embeddings.py     # RAG system with ChromaDB
│   │   └── corpus_builder.py # Corpus management
│   └── execution/
│       └── ssh_executor.py   # SSH command execution
├── corpus/
│   └── procedures/           # Analysis procedures (JSON)
├── .githooks/
│   └── pre-commit            # Security scanner for commits
├── scripts/
│   └── setup-hooks.sh        # Git hooks setup script
├── analyze.py                # CLI entry point
├── requirements.txt
├── .env.example
└── README.md
```

## Development Setup

After cloning, set up the git hooks to prevent accidental commits of sensitive information:

```bash
# Run the hooks setup script
./scripts/setup-hooks.sh
```

This enables a pre-commit hook that scans for:
- Private IP addresses
- API keys and credentials
- Personal file paths
- Environment files

## Safety Notes

- Always analyze malware in isolated VMs
- Never connect analysis VMs to production networks
- Snapshot VMs before dynamic analysis
- Defang IOCs in reports (use `[.]` for domains)

## Contributing

Contributions welcome! Areas of interest:
- Additional analysis procedures
- Support for Linux malware (REMnux integration)
- Enhanced IOC extraction
- MITRE ATT&CK auto-mapping

## License

MIT License

---

## Project Assessment

### What I Built
A RAG-based autonomous malware analysis agent that:
- Used ChromaDB vector database for retrieval
- Integrated Claude API for reasoning
- Executed tools via SSH on FLARE VM
- Generated analysis reports

### What I Learned

**Key Finding:** RAG agents excel at knowledge retrieval but struggle with complex reasoning tasks requiring synthesis across multiple data sources.

**The Test:** I analyzed the same AsyncRAT/VenomRAT sample twice:
1. **RAG Agent** (25 steps, 17 minutes): Failed to identify malware family, zero MITRE techniques mapped, minimal actionable output
2. **Claude Code Direct** (systematic approach, 10 minutes): Identified VenomRAT 6.X, mapped 15 MITRE techniques, extracted config, produced professional IR report

**Side-by-Side Results:**

| Analysis Aspect | RAG Agent | Claude Code |
|-----------------|-----------|-------------|
| Malware Family | Not identified | VenomRAT 6.X |
| Verdict | "No specific findings" | MALICIOUS - 95% confidence |
| MITRE Techniques | 0 | 15 mapped |
| Config Extraction | Decoded 1 string | Full AES key + persistence |
| Report Quality | Minimal JSON | Professional IR report |

**Why RAG Underperformed:**
- **No synthesis capability**: Listed data but couldn't connect findings to conclusions
- **Random tool selection**: No systematic methodology, tried tools without purpose
- **No domain reasoning**: Didn't understand what "Stub.exe" means (common RAT indicator)
- **Weak verdict generation**: Can't say "this is malicious because X, Y, Z"

**When RAG IS Valuable:**
- **Knowledge lookup**: "What MITRE technique matches this behavior?"
- **Historical comparison**: "Have we seen samples with this AES key before?"
- **Tool guidance**: "How do I configure CAPA for .NET analysis?"
- **Threat intel retrieval**: "What campaigns use AsyncRAT?"

**The Architecture Insight:**

```
RAG as orchestrator (what I built)
   RAG Agent -> decides what to do -> executes -> fails to synthesize

RAG as knowledge base (what works)
   Claude Code -> decides what to do -> queries RAG when needed -> synthesizes
```

**Bottom Line:** RAG is a reference library, not an analyst. Complex IR workflows need strong reasoning (Claude Code) PLUS specialized retrieval (RAG), not RAG alone.

### What's Next

This project validated an important architectural principle: **Use the right tool for the right job.**

For malware analysis automation, the winning combination is:
- **Claude Code** for reasoning, synthesis, and adaptive analysis
- **RAG** for historical lookups and specialized knowledge retrieval (when you have the corpus)
- **Computer use** for GUI tool interaction (future enhancement)

### Full Analysis

See **[PROJECT_ASSESSMENT.md](PROJECT_ASSESSMENT.md)** for:
- Detailed test methodology
- Complete side-by-side comparison
- Technical analysis of why RAG underperformed
- Specific use cases where RAG adds value
- Lessons learned for building AI-powered security tools
