"""
SSH Executor for FLARE VM
Executes commands on the isolated Windows analysis VM via Proxmox jump host.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class ExecutionResult:
    """Result of a command execution."""
    stdout: str
    stderr: str
    return_code: int
    success: bool

    def __str__(self):
        if self.success:
            return self.stdout
        return f"Error (code {self.return_code}): {self.stderr or self.stdout}"


class SSHExecutor:
    """Execute commands on FLARE VM via SSH through Proxmox jump host."""

    def __init__(self):
        self.flare_host = os.getenv("FLARE_VM_HOST", "192.168.1.100")
        self.flare_user = os.getenv("FLARE_VM_USER", "user")
        self.flare_password = os.getenv("FLARE_VM_PASSWORD", "password")
        self.jump_host = os.getenv("FLARE_VM_JUMP_HOST", "192.168.1.1")
        self.jump_user = os.getenv("FLARE_VM_JUMP_USER", "user")
        self.timeout = int(os.getenv("MAX_EXECUTION_TIME", "300"))

    def _build_ssh_command(self, cmd: str) -> list:
        """Build the SSH command with jump host."""
        # Escape single quotes in the command
        escaped_cmd = cmd.replace("'", "'\"'\"'")

        # Use sshpass for password auth, SSH through jump host
        return [
            "ssh",
            f"{self.jump_user}@{self.jump_host}",
            f"sshpass -p '{self.flare_password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {self.flare_user}@{self.flare_host} '{escaped_cmd}'"
        ]

    def execute(self, command: str, timeout: Optional[int] = None) -> ExecutionResult:
        """
        Execute a command on the FLARE VM.

        Args:
            command: The command to execute (cmd.exe or PowerShell)
            timeout: Optional timeout in seconds

        Returns:
            ExecutionResult with stdout, stderr, return code
        """
        timeout = timeout or self.timeout
        ssh_cmd = self._build_ssh_command(command)

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return ExecutionResult(
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                return_code=result.returncode,
                success=(result.returncode == 0)
            )

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                return_code=-1,
                success=False
            )
        except Exception as e:
            return ExecutionResult(
                stdout="",
                stderr=str(e),
                return_code=-1,
                success=False
            )

    def execute_powershell(self, script: str, timeout: Optional[int] = None) -> ExecutionResult:
        """
        Execute a PowerShell script on the FLARE VM.

        Args:
            script: PowerShell script content
            timeout: Optional timeout in seconds

        Returns:
            ExecutionResult
        """
        # Escape for PowerShell
        escaped_script = script.replace('"', '\\"')
        cmd = f'powershell -ExecutionPolicy Bypass -Command "{escaped_script}"'
        return self.execute(cmd, timeout)

    def list_tools(self, path: str = "C:\\Tools") -> ExecutionResult:
        """List available tools in the FLARE VM tools directory."""
        return self.execute_powershell(f"Get-ChildItem '{path}' | Select-Object Name")

    def check_file_exists(self, path: str) -> bool:
        """Check if a file exists on the FLARE VM."""
        result = self.execute_powershell(f"Test-Path '{path}'")
        return result.success and "True" in result.stdout

    def upload_file(self, local_path: str, remote_path: str) -> ExecutionResult:
        """
        Upload a file to the FLARE VM via SCP through jump host.

        Args:
            local_path: Path to local file
            remote_path: Destination path on FLARE VM

        Returns:
            ExecutionResult
        """
        # First copy to jump host, then to FLARE VM
        jump_tmp = f"/tmp/{Path(local_path).name}"

        # Copy to jump host
        scp_to_jump = subprocess.run(
            ["scp", local_path, f"{self.jump_user}@{self.jump_host}:{jump_tmp}"],
            capture_output=True,
            text=True
        )

        if scp_to_jump.returncode != 0:
            return ExecutionResult(
                stdout="",
                stderr=f"Failed to copy to jump host: {scp_to_jump.stderr}",
                return_code=scp_to_jump.returncode,
                success=False
            )

        # Copy from jump host to FLARE VM
        scp_to_flare = subprocess.run(
            [
                "ssh", f"{self.jump_user}@{self.jump_host}",
                f"sshpass -p '{self.flare_password}' scp -o StrictHostKeyChecking=no {jump_tmp} {self.flare_user}@{self.flare_host}:'{remote_path}'"
            ],
            capture_output=True,
            text=True
        )

        # Clean up jump host temp file
        subprocess.run(
            ["ssh", f"{self.jump_user}@{self.jump_host}", f"rm -f {jump_tmp}"],
            capture_output=True
        )

        return ExecutionResult(
            stdout="File uploaded successfully" if scp_to_flare.returncode == 0 else "",
            stderr=scp_to_flare.stderr,
            return_code=scp_to_flare.returncode,
            success=(scp_to_flare.returncode == 0)
        )

    def download_file(self, remote_path: str, local_path: str) -> ExecutionResult:
        """
        Download a file from the FLARE VM via SCP through jump host.

        Args:
            remote_path: Path on FLARE VM
            local_path: Local destination path

        Returns:
            ExecutionResult
        """
        jump_tmp = f"/tmp/{Path(remote_path).name}"

        # Copy from FLARE VM to jump host
        scp_from_flare = subprocess.run(
            [
                "ssh", f"{self.jump_user}@{self.jump_host}",
                f"sshpass -p '{self.flare_password}' scp -o StrictHostKeyChecking=no {self.flare_user}@{self.flare_host}:'{remote_path}' {jump_tmp}"
            ],
            capture_output=True,
            text=True
        )

        if scp_from_flare.returncode != 0:
            return ExecutionResult(
                stdout="",
                stderr=f"Failed to copy from FLARE VM: {scp_from_flare.stderr}",
                return_code=scp_from_flare.returncode,
                success=False
            )

        # Copy from jump host to local
        scp_to_local = subprocess.run(
            ["scp", f"{self.jump_user}@{self.jump_host}:{jump_tmp}", local_path],
            capture_output=True,
            text=True
        )

        # Clean up
        subprocess.run(
            ["ssh", f"{self.jump_user}@{self.jump_host}", f"rm -f {jump_tmp}"],
            capture_output=True
        )

        return ExecutionResult(
            stdout=f"File downloaded to {local_path}" if scp_to_local.returncode == 0 else "",
            stderr=scp_to_local.stderr,
            return_code=scp_to_local.returncode,
            success=(scp_to_local.returncode == 0)
        )

    def test_connection(self) -> ExecutionResult:
        """Test SSH connection to FLARE VM."""
        return self.execute("hostname")


# Convenience function for quick testing
def test_ssh():
    """Quick test of SSH connection."""
    executor = SSHExecutor()
    print("Testing SSH connection to FLARE VM...")

    result = executor.test_connection()
    if result.success:
        print(f"Connected to: {result.stdout}")
    else:
        print(f"Connection failed: {result.stderr}")

    print("\nListing tools directory...")
    tools = executor.list_tools()
    print(tools.stdout if tools.success else tools.stderr)

    return result.success


if __name__ == "__main__":
    test_ssh()
