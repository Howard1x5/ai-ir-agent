"""
Corpus Builder for AI IR Agent RAG System
Fetches and processes documentation from various sources.
"""

import os
import re
import json
import hashlib
import requests
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from bs4 import BeautifulSoup


@dataclass
class Document:
    """A document in the corpus."""
    id: str
    title: str
    content: str
    source: str
    source_type: str  # blog, mitre, tool, procedure
    url: Optional[str] = None
    metadata: Optional[Dict] = None

    def to_dict(self):
        return asdict(self)


class CorpusBuilder:
    """Build and manage the RAG corpus."""

    def __init__(self, corpus_dir: str = None):
        if corpus_dir is None:
            corpus_dir = Path(__file__).parent.parent.parent / "corpus"
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        for subdir in ["examples", "mitre", "tools", "procedures"]:
            (self.corpus_dir / subdir).mkdir(exist_ok=True)

    def _generate_id(self, content: str) -> str:
        """Generate a unique ID for a document."""
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def _clean_text(self, text: str) -> str:
        """Clean and normalize text."""
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        # Remove special characters but keep code-relevant ones
        text = re.sub(r'[^\w\s\-_.,:;!?()[\]{}\'\"<>/\\=+*&^%$#@`~|]', '', text)
        return text.strip()

    def fetch_blog_post(self, url: str) -> Optional[Document]:
        """Fetch and parse a blog post."""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')

            # Try to find the main content
            content_div = (
                soup.find('article') or
                soup.find('div', class_='post-content') or
                soup.find('div', class_='entry-content') or
                soup.find('main') or
                soup.find('body')
            )

            if not content_div:
                return None

            # Get title
            title_tag = soup.find('h1') or soup.find('title')
            title = title_tag.get_text().strip() if title_tag else url.split('/')[-1]

            # Extract text content
            # Remove script and style elements
            for script in content_div(['script', 'style', 'nav', 'footer', 'header']):
                script.decompose()

            content = content_div.get_text(separator='\n')
            content = self._clean_text(content)

            return Document(
                id=self._generate_id(url),
                title=title,
                content=content,
                source=url,
                source_type="blog",
                url=url
            )

        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None

    def fetch_boredhackerblog(self, max_posts: int = 20) -> List[Document]:
        """Fetch malware analysis posts from boredhackerblog.info."""
        documents = []
        base_url = "https://www.boredhackerblog.info"

        try:
            # Get the main page
            response = requests.get(base_url, timeout=30)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find post links
            links = soup.find_all('a', href=True)
            post_urls = []

            for link in links:
                href = link['href']
                # Look for post URLs (typically have year/month pattern)
                if re.search(r'/\d{4}/\d{2}/', href):
                    if href.startswith('/'):
                        href = base_url + href
                    if href not in post_urls and 'boredhackerblog' in href:
                        post_urls.append(href)

            print(f"Found {len(post_urls)} posts on boredhackerblog")

            for url in post_urls[:max_posts]:
                print(f"Fetching: {url}")
                doc = self.fetch_blog_post(url)
                if doc:
                    doc.source_type = "blog"
                    doc.metadata = {"blog": "boredhackerblog"}
                    documents.append(doc)

        except Exception as e:
            print(f"Error fetching boredhackerblog: {e}")

        return documents

    def add_local_blog_posts(self, blog_dir: str) -> List[Document]:
        """Add local blog posts from markdown files."""
        documents = []
        blog_path = Path(blog_dir)

        if not blog_path.exists():
            print(f"Blog directory not found: {blog_dir}")
            return documents

        for md_file in blog_path.glob("**/*.md"):
            try:
                content = md_file.read_text()

                # Extract title from frontmatter or first heading
                title_match = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', content, re.MULTILINE)
                if title_match:
                    title = title_match.group(1)
                else:
                    heading_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
                    title = heading_match.group(1) if heading_match else md_file.stem

                # Remove frontmatter
                content = re.sub(r'^---.*?---\s*', '', content, flags=re.DOTALL)

                documents.append(Document(
                    id=self._generate_id(str(md_file)),
                    title=title,
                    content=content,
                    source=str(md_file),
                    source_type="blog",
                    metadata={"local": True, "file": md_file.name}
                ))

            except Exception as e:
                print(f"Error reading {md_file}: {e}")

        return documents

    def create_ir_procedures(self) -> List[Document]:
        """Create standard IR/RE procedure documents."""
        procedures = [
            {
                "title": "Initial Malware Triage",
                "content": """
# Initial Malware Triage Procedure

## Step 1: File Identification
- Calculate hashes (MD5, SHA256) using: certutil -hashfile <file> SHA256
- Check file type with: file <sample> or TrID
- Look up hashes on VirusTotal, MalwareBazaar

## Step 2: Static Analysis Overview
- Strings extraction: strings <file> or FLOSS
- Check PE headers: pestudio, PE-bear
- Look for imports, exports, sections
- Identify packers/protectors: Detect It Easy (DIE)

## Step 3: Basic Dynamic Setup
- Snapshot the VM before execution
- Start Procmon with filters for the sample
- Start Process Hacker or Process Explorer
- Enable network capture (Wireshark/FakeNet-NG)

## Step 4: Execution and Monitoring
- Execute sample and observe behavior
- Note: Process creation, file operations, registry changes, network connections
- Capture IOCs: IPs, domains, file paths, registry keys

## Step 5: Documentation
- Screenshot key findings
- Export Procmon logs
- Document MITRE ATT&CK techniques observed
"""
            },
            {
                "title": "PowerShell Malware Analysis",
                "content": """
# PowerShell Malware Analysis Procedure

## Deobfuscation Techniques

### Base64 Encoded Commands
- Look for: -EncodedCommand, -enc, -e flags
- Decode: [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('...'))
- In CyberChef: From Base64 -> Decode Text (UTF-16LE)

### String Concatenation
- PowerShell often uses: "Down" + "load" + "String"
- Manually concatenate or use PowerShell ISE to evaluate

### Character Code Obfuscation
- [char]72 = 'H', [char]101 = 'e', etc.
- Evaluate arrays: [char[]]@(72,101,108,108,111) -join ''

### Invoke-Expression (IEX) Unwrapping
- Replace IEX/Invoke-Expression with Write-Output
- This reveals the code without executing it

## Tools
- PowerShell ISE (isolated VM only!)
- CyberChef for encoding/decoding
- PowerDecode for automated deobfuscation

## Common Indicators
- Download cradles: Invoke-WebRequest, Net.WebClient, BITS
- Execution: Invoke-Expression, & operator, . sourcing
- Persistence: ScheduledTask, Registry, WMI subscription
"""
            },
            {
                "title": "VBScript Malware Analysis",
                "content": """
# VBScript Malware Analysis Procedure

## Initial Analysis
- Open in text editor with syntax highlighting
- Search for: Execute, Eval, Run, Shell, GetObject, WScript

## Common Obfuscation Techniques

### String Operations
- Chr() function: Chr(72) & Chr(101) = "He"
- Asc() for encoding: Asc("A") = 65
- String reversal with StrReverse()

### Math-based Obfuscation
- Subtraction/Addition: Chr(73-1) = "H"
- XOR operations

### Function Nesting
- Track call order: OuterFunc(MiddleFunc(InnerFunc(data)))
- Inner function executes first on the data

## WMI Execution
- GetObject("winmgmts:...") indicates WMI usage
- Win32_Process.Create() spawns processes
- Common for launching PowerShell stages

## CyberChef Recipe for VBScript
1. Reverse (if StrReverse used)
2. ADD -1 (DECIMAL) for Chr() offset
3. From Hex (if hex encoded)
4. XOR with extracted key
"""
            },
            {
                "title": "PE Executable Analysis",
                "content": """
# PE Executable Analysis Procedure

## Tools to Use
- pestudio: Initial triage, indicators
- PE-bear: Header analysis
- Detect It Easy: Packer/compiler detection
- IDA Free or Ghidra: Disassembly
- x64dbg: Dynamic debugging

## Static Analysis Steps

### 1. File Properties
- File size, compile timestamp
- Check for anomalies (future dates, round sizes)

### 2. Header Analysis
- Entry point location
- Section names (.text, .data, .rsrc, .reloc)
- Suspicious sections: high entropy, unusual names

### 3. Import Analysis
- Network: ws2_32.dll, wininet.dll, winhttp.dll
- Process: kernel32.dll CreateProcess, VirtualAlloc
- Crypto: advapi32.dll CryptEncrypt/Decrypt
- Anti-debug: IsDebuggerPresent, CheckRemoteDebuggerPresent

### 4. Strings Analysis
- Use FLOSS for better string extraction
- Look for: URLs, IPs, file paths, registry keys, commands

## Dynamic Analysis

### Debugging with x64dbg
- Set breakpoints on suspicious APIs
- Track memory allocations (VirtualAlloc)
- Monitor network calls

### API Monitoring
- API Monitor for detailed call logging
- Procmon for file/registry/network activity
"""
            },
            {
                "title": "Network IOC Extraction",
                "content": """
# Network IOC Extraction Procedure

## Capture Setup
- FakeNet-NG: Simulates internet services, captures traffic
- Wireshark: Full packet capture
- INetSim (REMnux): Simulated internet services

## DNS Indicators
- Extract queried domains from Wireshark: dns.qry.name
- Check for DGA patterns (random-looking domains)
- Note: A, AAAA, TXT, CNAME record types

## HTTP/HTTPS Indicators
- URLs, User-Agents, Headers
- POST data (potential exfiltration)
- For HTTPS: May need to MITM or check memory

## IP Addresses
- C2 servers, staging servers
- Geolocation can indicate actor origin
- Check against threat intelligence

## Defanging IOCs
- URLs: hxxps:// instead of https://
- IPs: 192.168.1[.]1 instead of 192.168.1.1
- Domains: evil[.]com instead of evil.com

## Tools
- Wireshark filters: http.request, dns, tcp.port==443
- tshark for command-line extraction
- NetworkMiner for artifact extraction
"""
            }
        ]

        documents = []
        for proc in procedures:
            documents.append(Document(
                id=self._generate_id(proc["title"]),
                title=proc["title"],
                content=proc["content"],
                source="generated",
                source_type="procedure"
            ))

        return documents

    def save_documents(self, documents: List[Document], subdir: str = "examples"):
        """Save documents to corpus directory."""
        output_dir = self.corpus_dir / subdir
        output_dir.mkdir(exist_ok=True)

        for doc in documents:
            filename = f"{doc.id}_{re.sub(r'[^a-zA-Z0-9]', '_', doc.title)[:50]}.json"
            filepath = output_dir / filename

            with open(filepath, 'w') as f:
                json.dump(doc.to_dict(), f, indent=2)

        print(f"Saved {len(documents)} documents to {output_dir}")

    def load_all_documents(self) -> List[Document]:
        """Load all documents from the corpus."""
        documents = []

        for json_file in self.corpus_dir.glob("**/*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    documents.append(Document(**data))
            except Exception as e:
                print(f"Error loading {json_file}: {e}")

        return documents

    def build_corpus(self, include_remote: bool = True, blog_dir: str = None):
        """Build the complete corpus."""
        print("Building RAG corpus...")

        # 1. Create IR procedures
        print("\n1. Creating IR/RE procedures...")
        procedures = self.create_ir_procedures()
        self.save_documents(procedures, "procedures")

        # 2. Add local blog posts
        if blog_dir:
            print(f"\n2. Adding local blog posts from {blog_dir}...")
            local_blogs = self.add_local_blog_posts(blog_dir)
            self.save_documents(local_blogs, "examples")

        # 3. Fetch remote blogs (optional)
        if include_remote:
            print("\n3. Fetching boredhackerblog posts...")
            remote_blogs = self.fetch_boredhackerblog(max_posts=10)
            self.save_documents(remote_blogs, "examples")

        # Summary
        all_docs = self.load_all_documents()
        print(f"\nCorpus built: {len(all_docs)} total documents")

        return all_docs


if __name__ == "__main__":
    builder = CorpusBuilder()

    # Build corpus (optionally pass blog_dir for local markdown posts)
    # Example: builder.build_corpus(include_remote=True, blog_dir="/path/to/blog/_posts")
    builder.build_corpus(include_remote=True)
