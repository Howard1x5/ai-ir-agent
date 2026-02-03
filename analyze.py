#!/usr/bin/env python3
"""
AI IR Agent - Command Line Interface
Usage: python analyze.py <sample_path_on_vm> [sample_name]

Safety Features:
  - Detonation guardrails prevent accidental malware execution
  - Use --allow-detonation on isolated VM for dynamic analysis
  - Network detonation requires explicit --allow-network-detonation flag
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.agent import IRAgent, DetonationBlockedError


def main():
    parser = argparse.ArgumentParser(
        description="AI IR Agent - Automated Malware Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a sample (static analysis only - safe)
  python analyze.py "C:\\Samples\\rats\\asyncrat.exe"

  # Analyze with custom name
  python analyze.py "C:\\Samples\\rats\\sample.bin" "suspicious_dropper"

  # Test mode (verifies connection)
  python analyze.py --test

  # Dynamic analysis on isolated detonation VM (DANGEROUS)
  python analyze.py "C:\\Samples\\rats\\malware.exe" --allow-detonation

  # Network-enabled detonation for secondary payloads (VERY DANGEROUS)
  python analyze.py "C:\\Samples\\loaders\\dropper.exe" --allow-detonation --allow-network-detonation

Safety:
  By default, the agent will BLOCK any attempt to execute malware.
  Use --allow-detonation ONLY on the isolated detonation VM (see DETONATION_VM_HOST in .env).
        """
    )

    parser.add_argument(
        "sample_path",
        nargs="?",
        help="Path to the sample on the FLARE VM"
    )
    parser.add_argument(
        "sample_name",
        nargs="?",
        help="Friendly name for the sample (optional)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test mode - verify connections without analyzing"
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=20,
        help="Maximum analysis steps (default: 20)"
    )
    parser.add_argument(
        "--allow-detonation",
        action="store_true",
        help="Allow malware execution (ONLY use on isolated detonation VM!)"
    )
    parser.add_argument(
        "--allow-network-detonation",
        action="store_true",
        help="Allow detonation with network access (DANGEROUS - for secondary payload analysis)"
    )

    args = parser.parse_args()

    # Safety warning for detonation flags
    if args.allow_detonation:
        print("\n" + "!" * 60)
        print("WARNING: --allow-detonation flag is set!")
        print("Malware execution will be ALLOWED on this VM.")
        print("Ensure you are on the ISOLATED detonation VM (see DETONATION_VM_HOST)")
        print("!" * 60 + "\n")

    if args.allow_network_detonation:
        print("\n" + "!" * 60)
        print("CRITICAL WARNING: --allow-network-detonation flag is set!")
        print("Malware may connect to the internet and download payloads!")
        print("This should ONLY be used for controlled secondary payload analysis.")
        print("!" * 60 + "\n")

    print("=" * 60)
    print("AI IR Agent - Automated Malware Analysis")
    print("=" * 60)

    if args.test:
        print("\n[TEST MODE] Verifying connections...\n")

        # Test SSH
        print("1. Testing SSH to FLARE VM...")
        from src.execution.ssh_executor import SSHExecutor
        executor = SSHExecutor()
        result = executor.test_connection()
        if result.success:
            print(f"   ✓ Connected to: {result.stdout}")
        else:
            print(f"   ✗ Failed: {result.stderr}")
            sys.exit(1)

        # Test RAG
        print("\n2. Testing RAG system...")
        from src.rag.embeddings import RAGSystem
        rag = RAGSystem()
        if rag.collection.count() > 0:
            print(f"   ✓ RAG indexed: {rag.collection.count()} chunks")
        else:
            print("   ! RAG not indexed, indexing now...")
            rag.index_corpus()
            print(f"   ✓ RAG indexed: {rag.collection.count()} chunks")

        # Test Claude API
        print("\n3. Testing Claude API...")
        import anthropic
        import os
        from dotenv import load_dotenv
        load_dotenv()
        try:
            client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=50,
                messages=[{"role": "user", "content": "Say 'API OK' if you can read this."}]
            )
            print(f"   ✓ Claude API working: {response.content[0].text[:50]}")
        except Exception as e:
            print(f"   ✗ Claude API failed: {e}")
            sys.exit(1)

        print("\n" + "=" * 60)
        print("All systems operational!")
        print("=" * 60)
        return

    if not args.sample_path:
        parser.print_help()
        print("\nError: sample_path is required (or use --test)")
        sys.exit(1)

    # Run analysis with safety guardrails
    try:
        agent = IRAgent(
            max_steps=args.max_steps,
            allow_detonation=args.allow_detonation,
            allow_network_detonation=args.allow_network_detonation
        )

        sample_name = args.sample_name or Path(args.sample_path).name
        report = agent.analyze_sample(args.sample_path, sample_name)

        # Save report
        report_path = agent.save_report(report)

        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"\nSample: {report.sample_name}")
        print(f"Steps: {len(report.steps)}")
        print(f"\nSummary:\n{report.summary}")
        print(f"\nFull report: {report_path}")

    except DetonationBlockedError as e:
        print("\n" + "=" * 60)
        print("ANALYSIS HALTED - DETONATION BLOCKED")
        print("=" * 60)
        print(f"\nReason: {e}")
        print("\nStatic analysis may have completed. Check output above for findings.")
        print("To proceed with dynamic analysis, follow the instructions above.")
        sys.exit(2)


if __name__ == "__main__":
    main()
