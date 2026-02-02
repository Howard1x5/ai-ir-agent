"""
AI IR Agent - Main Agent Orchestrator
Coordinates RAG retrieval, Claude API, and VM execution for malware analysis.
"""

import os
import json
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
import anthropic

# Local imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.rag.embeddings import RAGSystem
from src.execution.ssh_executor import SSHExecutor, ExecutionResult

load_dotenv()


@dataclass
class AnalysisStep:
    """A single step in the analysis."""
    step_number: int
    action: str
    command: Optional[str]
    result: Optional[str]
    reasoning: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class AnalysisReport:
    """Complete analysis report."""
    sample_name: str
    sample_hash: Optional[str]
    start_time: str
    steps: List[AnalysisStep]
    findings: List[str]
    iocs: Dict[str, List[str]]
    mitre_techniques: List[str]
    summary: str
    end_time: Optional[str] = None


class IRAgent:
    """AI-powered Incident Response Agent for malware analysis."""

    SYSTEM_PROMPT = """You are an expert malware analyst and incident responder. You have access to:
1. A Windows FLARE VM with analysis tools (Procmon, x64dbg, pestudio, strings, etc.)
2. The ability to execute PowerShell and cmd commands on the VM
3. A knowledge base of malware analysis procedures and techniques

Your task is to analyze malware samples systematically and safely.

## Guidelines
- Always work methodically: identify, analyze statically, then dynamically
- Document all findings with IOCs (hashes, IPs, domains, file paths, registry keys)
- Map findings to MITRE ATT&CK techniques when possible
- Be thorough but efficient - don't repeat steps unnecessarily
- If a command fails, try an alternative approach

## Available Tools on FLARE VM
- C:\\Tools\\SysinternalsSuite\\ (Procmon, Process Explorer, strings, etc.)
- C:\\Tools\\pestudio\\
- C:\\Tools\\x64dbg\\
- PowerShell with full capabilities
- certutil for hashing
- Standard Windows commands

## Command Format
When you want to execute a command, output it in this exact format:
```execute
<your command here>
```

When you're done with analysis, output:
```complete
<summary of findings>
```

## Analysis Flow
1. File identification (hashes, file type)
2. Static analysis (strings, imports, sections)
3. Dynamic analysis (if safe and necessary)
4. IOC extraction
5. Report generation
"""

    def __init__(self, max_steps: int = 20):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.executor = SSHExecutor()
        self.rag = RAGSystem()
        self.max_steps = max_steps
        self.conversation_history: List[Dict] = []

        # Ensure RAG is indexed
        if self.rag.collection.count() == 0:
            print("Indexing RAG corpus...")
            self.rag.index_corpus()

    def _get_rag_context(self, query: str) -> str:
        """Get relevant context from RAG system."""
        return self.rag.get_context_for_query(query, max_tokens=3000)

    def _extract_command(self, response: str) -> Optional[str]:
        """Extract command from response if present."""
        match = re.search(r'```execute\n(.+?)\n```', response, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None

    def _is_complete(self, response: str) -> Tuple[bool, Optional[str]]:
        """Check if analysis is complete and extract summary."""
        match = re.search(r'```complete\n(.+?)\n```', response, re.DOTALL)
        if match:
            return True, match.group(1).strip()
        return False, None

    def _call_claude(self, user_message: str, rag_context: str = "") -> str:
        """Call Claude API with conversation history."""
        # Add RAG context to system prompt if available
        system = self.SYSTEM_PROMPT
        if rag_context:
            system += f"\n\n## Relevant Knowledge Base Context\n{rag_context}"

        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=system,
            messages=self.conversation_history
        )

        assistant_message = response.content[0].text
        self.conversation_history.append({
            "role": "assistant",
            "content": assistant_message
        })

        return assistant_message

    def _format_execution_result(self, result: ExecutionResult) -> str:
        """Format execution result for conversation."""
        if result.success:
            output = result.stdout if result.stdout else "(No output)"
            return f"Command executed successfully.\n\nOutput:\n```\n{output}\n```"
        else:
            return f"Command failed (exit code {result.return_code}).\n\nError:\n```\n{result.stderr}\n```"

    def analyze_sample(self, sample_path: str, sample_name: str = None) -> AnalysisReport:
        """
        Analyze a malware sample.

        Args:
            sample_path: Path to the sample on the FLARE VM
            sample_name: Optional friendly name for the sample

        Returns:
            AnalysisReport with findings
        """
        if not sample_name:
            sample_name = Path(sample_path).name

        print(f"\n{'='*60}")
        print(f"Starting analysis of: {sample_name}")
        print(f"Path: {sample_path}")
        print(f"{'='*60}\n")

        # Initialize report
        report = AnalysisReport(
            sample_name=sample_name,
            sample_hash=None,
            start_time=datetime.now().isoformat(),
            steps=[],
            findings=[],
            iocs={"hashes": [], "ips": [], "domains": [], "files": [], "registry": []},
            mitre_techniques=[],
            summary=""
        )

        # Reset conversation
        self.conversation_history = []

        # Get initial RAG context
        initial_query = f"How to analyze malware sample: {sample_name}"
        rag_context = self._get_rag_context(initial_query)

        # Initial prompt
        initial_prompt = f"""I need you to analyze a malware sample.

Sample name: {sample_name}
Sample path on FLARE VM: {sample_path}

Please begin the analysis by:
1. First, verify the file exists and get its hash
2. Identify the file type
3. Proceed with appropriate static analysis

Start with the file hash command."""

        step_number = 0
        complete = False

        while step_number < self.max_steps and not complete:
            step_number += 1
            print(f"\n--- Step {step_number} ---")

            # Get Claude's response
            if step_number == 1:
                response = self._call_claude(initial_prompt, rag_context)
            else:
                # For subsequent steps, get fresh RAG context based on current state
                current_query = f"malware analysis {sample_name} " + (report.findings[-1] if report.findings else "")
                rag_context = self._get_rag_context(current_query)
                response = self._call_claude(
                    f"Previous command result:\n{last_result}\n\nContinue the analysis.",
                    rag_context
                )

            print(f"Agent response:\n{response[:500]}...")

            # Check if complete
            complete, summary = self._is_complete(response)
            if complete:
                report.summary = summary
                break

            # Extract and execute command
            command = self._extract_command(response)
            if command:
                print(f"\nExecuting: {command}")
                result = self.executor.execute(command)
                last_result = self._format_execution_result(result)
                print(f"Result: {last_result[:300]}...")

                # Record step
                step = AnalysisStep(
                    step_number=step_number,
                    action="execute_command",
                    command=command,
                    result=result.stdout if result.success else result.stderr,
                    reasoning=response[:200]
                )
                report.steps.append(step)

                # Extract IOCs from output
                self._extract_iocs(result.stdout, report)
            else:
                # No command, record as analysis step
                step = AnalysisStep(
                    step_number=step_number,
                    action="analysis",
                    command=None,
                    result=None,
                    reasoning=response[:500]
                )
                report.steps.append(step)
                last_result = "No command executed. Please provide a command to run."

        report.end_time = datetime.now().isoformat()

        # If we hit max steps, generate summary
        if not report.summary:
            report.summary = self._generate_summary(report)

        return report

    def _extract_iocs(self, text: str, report: AnalysisReport):
        """Extract IOCs from command output."""
        if not text:
            return

        # IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        report.iocs["ips"].extend([ip for ip in ips if ip not in report.iocs["ips"]])

        # Domains (simple pattern)
        domains = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', text.lower())
        report.iocs["domains"].extend([d for d in domains if d not in report.iocs["domains"]])

        # Hashes (MD5, SHA1, SHA256)
        hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)
        report.iocs["hashes"].extend([h for h in hashes if h not in report.iocs["hashes"]])

        # File paths
        paths = re.findall(r'[A-Za-z]:\\[^\s<>"|?*]+', text)
        report.iocs["files"].extend([p for p in paths if p not in report.iocs["files"]])

    def _generate_summary(self, report: AnalysisReport) -> str:
        """Generate a summary if analysis didn't complete naturally."""
        findings = "\n".join(f"- {f}" for f in report.findings) if report.findings else "No specific findings recorded."
        iocs = []
        for ioc_type, values in report.iocs.items():
            if values:
                iocs.append(f"{ioc_type}: {', '.join(values[:5])}")
        ioc_summary = "\n".join(iocs) if iocs else "No IOCs extracted."

        return f"""Analysis completed after {len(report.steps)} steps.

Findings:
{findings}

IOCs:
{ioc_summary}

Note: Analysis may be incomplete. Review steps for details."""

    def save_report(self, report: AnalysisReport, output_dir: str = None) -> str:
        """Save analysis report to JSON file."""
        if not output_dir:
            output_dir = Path(__file__).parent.parent.parent / "reports"
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)

        filename = f"{report.sample_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = output_dir / filename

        # Convert to dict
        report_dict = {
            "sample_name": report.sample_name,
            "sample_hash": report.sample_hash,
            "start_time": report.start_time,
            "end_time": report.end_time,
            "steps": [
                {
                    "step_number": s.step_number,
                    "action": s.action,
                    "command": s.command,
                    "result": s.result,
                    "reasoning": s.reasoning,
                    "timestamp": s.timestamp
                }
                for s in report.steps
            ],
            "findings": report.findings,
            "iocs": report.iocs,
            "mitre_techniques": report.mitre_techniques,
            "summary": report.summary
        }

        with open(filepath, 'w') as f:
            json.dump(report_dict, f, indent=2)

        print(f"\nReport saved to: {filepath}")
        return str(filepath)


def main():
    """Main entry point for testing."""
    print("AI IR Agent - Malware Analysis System")
    print("="*50)

    # Initialize agent
    agent = IRAgent()

    # Test with EICAR (safe test file)
    print("\nTo test, you would run:")
    print('agent.analyze_sample("C:\\\\Users\\\\analyst\\\\Desktop\\\\sample.exe", "test_sample")')


if __name__ == "__main__":
    main()
