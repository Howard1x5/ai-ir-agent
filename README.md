# AI IR Agent

An AI-powered Incident Response and Malware Analysis agent that uses RAG (Retrieval-Augmented Generation) to provide context-aware analysis capabilities.

## Overview

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
