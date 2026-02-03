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


class DetonationGuard:
    """
    Safety guardrails to prevent accidental malware detonation.

    Rules:
    - Block execution of .exe/.dll/.ps1/.vbs/.js from C:\Samples\ or unknown locations
    - Allow tools from C:\Tools\ and known safe directories
    - Require --allow-detonation flag and detonation VM for actual execution
    - Network detonation requires explicit --allow-network-detonation
    """

    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = {'.exe', '.dll', '.ps1', '.vbs', '.vbe', '.js', '.jse',
                           '.bat', '.cmd', '.scr', '.pif', '.com', '.msi', '.hta'}

    # Paths where samples live - executing from here is ALWAYS dangerous
    SAMPLE_PATHS = ['c:\\samples', 'c:\\users\\analyst\\downloads', 'c:\\temp\\samples']

    # Safe tool directories - executing from here is allowed
    SAFE_TOOL_PATHS = ['c:\\tools', 'c:\\program files', 'c:\\program files (x86)',
                       'c:\\windows\\system32', 'c:\\windows\\syswow64']

    # Safe PowerShell cmdlets that don't execute anything
    SAFE_PS_CMDLETS = {
        'get-filehash', 'get-content', 'get-childitem', 'get-item', 'get-itemproperty',
        'select-object', 'select-string', 'where-object', 'format-list', 'format-table',
        'out-file', 'out-string', 'test-path', 'measure-object', 'sort-object',
        'convertto-json', 'convertfrom-json', 'export-csv', 'set-content', 'add-content',
        'new-item', 'remove-item', 'copy-item', 'move-item', 'rename-item'
    }

    # Safe Windows commands
    SAFE_COMMANDS = {
        'dir', 'type', 'certutil', 'hostname', 'ipconfig', 'netstat', 'tasklist',
        'whoami', 'systeminfo', 'reg', 'wmic', 'findstr', 'fc', 'comp', 'tree',
        'attrib', 'icacls', 'where', 'echo', 'set', 'ver'
    }

    def __init__(self, current_vm_ip: str, detonation_vm_ip: str):
        self.current_vm_ip = current_vm_ip
        self.detonation_vm_ip = detonation_vm_ip
        self.is_detonation_vm = (current_vm_ip == detonation_vm_ip)

    def _normalize_path(self, path: str) -> str:
        """Normalize path for comparison."""
        return path.lower().replace('/', '\\').rstrip('\\')

    def _extract_executable_path(self, command: str) -> Optional[str]:
        """Extract the executable path from a command."""
        cmd_lower = command.lower().strip()

        # Check for direct executable paths
        # Pattern: path\to\file.exe or "path\to\file.exe"
        exe_pattern = r'["\']?([a-z]:\\[^"\'<>|*?\n]+\.(?:exe|dll|ps1|vbs|vbe|js|jse|bat|cmd|scr|pif|com|msi|hta))["\']?'
        match = re.search(exe_pattern, cmd_lower)
        if match:
            return match.group(1)

        # Check for PowerShell execution of scripts
        if 'powershell' in cmd_lower:
            # Look for -file parameter
            file_match = re.search(r'-file\s+["\']?([^"\'<>|*?\s]+)["\']?', cmd_lower)
            if file_match:
                return file_match.group(1)
            # Look for & "path" execution
            invoke_match = re.search(r'&\s*["\']([^"\']+)["\']', cmd_lower)
            if invoke_match:
                return invoke_match.group(1)

        return None

    def _is_path_in_samples(self, path: str) -> bool:
        """Check if path is in a samples directory."""
        norm_path = self._normalize_path(path)
        for sample_path in self.SAMPLE_PATHS:
            if norm_path.startswith(sample_path):
                return True
        return False

    def _is_path_in_safe_tools(self, path: str) -> bool:
        """Check if path is in a safe tools directory."""
        norm_path = self._normalize_path(path)
        for safe_path in self.SAFE_TOOL_PATHS:
            if norm_path.startswith(safe_path):
                return True
        return False

    def _is_safe_powershell_command(self, command: str) -> bool:
        """Check if a PowerShell command uses only safe cmdlets."""
        cmd_lower = command.lower()

        # If it's executing a script file, not safe
        if '-file' in cmd_lower or '.ps1' in cmd_lower:
            return False

        # Check if any dangerous patterns exist
        dangerous_patterns = [
            'invoke-expression', 'iex', 'invoke-command', 'icm',
            'start-process', 'invoke-webrequest', 'invoke-restmethod',
            'downloadstring', 'downloadfile', 'new-object net.webclient',
            '& ', '. .\\', 'powershell -e', '-encodedcommand', '-enc '
        ]
        for pattern in dangerous_patterns:
            if pattern in cmd_lower:
                return False

        return True

    def _is_safe_base_command(self, command: str) -> bool:
        """Check if the base command is safe."""
        cmd_lower = command.lower().strip()

        # Get the first word/command
        first_word = cmd_lower.split()[0] if cmd_lower.split() else ''

        # Strip quotes and path
        if '\\' in first_word:
            first_word = first_word.split('\\')[-1]
        first_word = first_word.strip('"\'')

        # Remove .exe extension for comparison
        if first_word.endswith('.exe'):
            first_word = first_word[:-4]

        return first_word in self.SAFE_COMMANDS

    def check_command(self, command: str) -> Tuple[bool, str]:
        """
        Check if a command is safe to execute.

        Returns:
            Tuple of (is_safe, reason)
            - If safe: (True, "")
            - If dangerous: (False, "reason why blocked")
        """
        cmd_lower = command.lower().strip()

        # Check for safe base commands (dir, certutil, etc.)
        if self._is_safe_base_command(command):
            return True, ""

        # Check for safe PowerShell commands
        if cmd_lower.startswith('powershell'):
            if self._is_safe_powershell_command(command):
                return True, ""

        # Extract any executable path from the command
        exe_path = self._extract_executable_path(command)

        if exe_path:
            # Check if it's running something from Samples folder
            if self._is_path_in_samples(exe_path):
                return False, f"DETONATION BLOCKED: Attempting to execute file from samples directory: {exe_path}"

            # Check if it's running something from safe tools folder
            if self._is_path_in_safe_tools(exe_path):
                return True, ""

            # Unknown location - block it
            ext = os.path.splitext(exe_path)[1].lower()
            if ext in self.DANGEROUS_EXTENSIONS:
                return False, f"DETONATION BLOCKED: Attempting to execute {ext} file from unknown location: {exe_path}"

        # Check for direct execution attempts without full path
        for ext in self.DANGEROUS_EXTENSIONS:
            if f'\\samples\\' in cmd_lower and ext in cmd_lower:
                return False, f"DETONATION BLOCKED: Command appears to execute sample file"

        # Default: allow (it's probably a safe analysis command)
        return True, ""

    def get_detonation_instructions(self, command: str, sample_path: str) -> str:
        """Get instructions for safe detonation."""
        return f"""
================================================================================
                        DETONATION SAFEGUARD TRIGGERED
================================================================================

BLOCKED COMMAND: {command}

CURRENT VM: {self.current_vm_ip} (Internet-connected analysis VM)
DETONATION VM: {self.detonation_vm_ip} (Isolated/air-gapped)

This command would execute the malware sample. For safety, detonation must occur
on the isolated VM without network connectivity.

TO PROCEED WITH DETONATION:
1. Move the sample to VM {self.detonation_vm_ip}:
   - Sample: {sample_path}
   - Destination: C:\\Samples\\ on VM {self.detonation_vm_ip}

2. Re-run the analysis on the detonation VM with the --allow-detonation flag:
   python analyze.py "{sample_path}" --allow-detonation --vm {self.detonation_vm_ip}

3. For network-enabled detonation (secondary payloads), add:
   --allow-network-detonation (requires manual VM network configuration)

================================================================================
ANALYSIS ABORTED - No malware was executed
================================================================================
"""


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


class DetonationBlockedError(Exception):
    """Raised when a detonation attempt is blocked by guardrails."""
    pass


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

    def __init__(self, max_steps: int = 20, allow_detonation: bool = False,
                 allow_network_detonation: bool = False):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.executor = SSHExecutor()
        self.rag = RAGSystem()
        self.max_steps = max_steps
        self.allow_detonation = allow_detonation
        self.allow_network_detonation = allow_network_detonation
        self.conversation_history: List[Dict] = []

        # VM configuration for detonation safety
        self.current_vm_ip = os.getenv("FLARE_VM_HOST", "192.168.1.100")
        self.detonation_vm_ip = os.getenv("DETONATION_VM_HOST", "192.168.1.110")

        # Initialize detonation guard
        self.guard = DetonationGuard(self.current_vm_ip, self.detonation_vm_ip)

        # Ensure RAG is indexed
        if self.rag.collection.count() == 0:
            print("Indexing RAG corpus...")
            self.rag.index_corpus()

        # Print safety status
        print(f"\n[SAFETY] Current VM: {self.current_vm_ip}")
        print(f"[SAFETY] Detonation VM: {self.detonation_vm_ip}")
        print(f"[SAFETY] Allow detonation: {self.allow_detonation}")
        print(f"[SAFETY] Allow network detonation: {self.allow_network_detonation}")
        if not self.allow_detonation:
            print("[SAFETY] Detonation guardrails ACTIVE - malware execution will be blocked")

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
                print(f"\nProposed command: {command}")

                # Check detonation guardrails
                is_safe, block_reason = self.guard.check_command(command)

                if not is_safe:
                    if self.allow_detonation and self.guard.is_detonation_vm:
                        # Detonation allowed on detonation VM
                        print(f"[SAFETY] Detonation command detected but ALLOWED (--allow-detonation on detonation VM)")
                    elif self.allow_detonation and not self.guard.is_detonation_vm:
                        # Detonation flag set but wrong VM
                        print(f"\n{self.guard.get_detonation_instructions(command, sample_path)}")
                        raise DetonationBlockedError(
                            f"Detonation blocked: Not on detonation VM. Current: {self.current_vm_ip}, Required: {self.detonation_vm_ip}"
                        )
                    else:
                        # Detonation not allowed
                        print(f"\n{self.guard.get_detonation_instructions(command, sample_path)}")
                        raise DetonationBlockedError(block_reason)

                print(f"[SAFETY] Command approved - executing...")
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
