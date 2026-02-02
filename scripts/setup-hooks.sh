#!/bin/bash
# Setup script for git hooks
# Run this after cloning the repository

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "Setting up git hooks..."

# Configure git to use our custom hooks directory
git config core.hooksPath "$REPO_ROOT/.githooks"

echo "Git hooks configured successfully!"
echo "The pre-commit hook will now scan for private information before each commit."
