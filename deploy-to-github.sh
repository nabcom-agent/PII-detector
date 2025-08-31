#!/bin/bash

# PII Detector - GitHub Deployment Script
# This script will initialize git, add files, and push to GitHub

echo "🚀 Starting GitHub deployment for PII Detector..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Repository URL
REPO_URL="https://github.com/nabcom-agent/PII-detector.git"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if git is installed
if ! command -v git &> /dev/null; then
    print_error "Git is not installed. Please install Git first."
    exit 1
fi

print_status "Git is available. Proceeding with deployment..."

# Navigate to project directory
cd /Users/nabillab/Downloads/exported-assets

# Initialize git repository if not already done
if [ ! -d ".git" ]; then
    print_status "Initializing Git repository..."
    git init
    print_success "Git repository initialized"
else
    print_status "Git repository already exists"
fi

# Add remote origin if not already added
if ! git remote get-url origin &> /dev/null; then
    print_status "Adding remote origin..."
    git remote add origin $REPO_URL
    print_success "Remote origin added: $REPO_URL"
else
    print_status "Remote origin already exists"
    # Update remote URL to make sure it's correct
    git remote set-url origin $REPO_URL
    print_success "Remote origin URL updated"
fi

# Check current branch and create main if needed
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "none")
if [ "$CURRENT_BRANCH" = "none" ] || [ "$CURRENT_BRANCH" = "master" ]; then
    print_status "Creating/switching to main branch..."
    git checkout -b main 2>/dev/null || git checkout main 2>/dev/null
fi

# Remove the zip file from tracking to keep repo clean
if [ -f "pii-encryption-tool.zip.zip" ]; then
    print_status "Removing zip file from repository..."
    git rm --cached pii-encryption-tool.zip.zip 2>/dev/null || true
fi

# Stage all files
print_status "Staging files for commit..."
git add .

# Check if there are changes to commit
if git diff --staged --quiet; then
    print_warning "No changes to commit. Repository is up to date."
else
    # Create commit with detailed message
    print_status "Creating commit..."
    git commit -m "Initial commit: PII Detection & Encryption Tool

✨ Features:
- 25+ PII pattern detection types with production-grade validation
- Luhn algorithm for credit card validation
- SSN validation with invalid prefix exclusion
- Multiple security processing methods (mask, hash, encrypt, redact)
- Enterprise-ready UI with full accessibility support
- Context-aware detection to avoid false positives
- Large document processing capability (1M+ characters)
- Select All/Unselect All toggle functionality
- Comprehensive documentation and README

🛡️ Security:
- Web Crypto API integration for secure operations
- SHA-256 hashing with cryptographic salt
- AES-GCM encryption with PBKDF2 key derivation
- JSON structure protection during processing
- Input validation and comprehensive error handling

🎨 UI/UX:
- Responsive design with mobile-first approach
- Dark/light mode theme compatibility
- WCAG 2.1 AA accessibility compliance
- Real-time visual feedback and highlighting
- Progress indicators for long operations
- Modern CSS design system with custom properties

📋 Technical:
- Vanilla JavaScript (ES6+) - no dependencies
- Modular CSS architecture with BEM methodology
- Semantic HTML5 with proper ARIA attributes
- Performance optimized with chunked processing
- Cross-browser compatibility (Chrome, Firefox, Safari, Edge)

🔧 Tools Included:
- Demo test data (15K characters)
- Pattern development utilities
- Comprehensive documentation
- Git configuration and deployment scripts"

    print_success "Commit created successfully"
fi

# Push to GitHub
print_status "Pushing to GitHub repository..."
if git push -u origin main; then
    print_success "Successfully pushed to GitHub! 🎉"
    echo ""
    echo "🌐 Your repository is now available at:"
    echo "   $REPO_URL"
    echo ""
    echo "🔧 Next steps:"
    echo "   1. Visit your GitHub repository"
    echo "   2. Enable GitHub Pages for live demo"
    echo "   3. Add repository description and topics"
    echo "   4. Consider adding a license file"
    echo ""
    print_success "Deployment completed successfully! ✅"
else
    print_error "Failed to push to GitHub. This might be due to:"
    echo "   • Authentication required (use personal access token)"
    echo "   • Repository already has content (try: git pull origin main --allow-unrelated-histories)"
    echo "   • Network connectivity issues"
    echo ""
    echo "🔧 To resolve authentication issues:"
    echo "   1. Generate a Personal Access Token at: https://github.com/settings/tokens"
    echo "   2. Use token as password when prompted"
    echo "   OR"
    echo "   3. Set up SSH keys for GitHub"
    echo ""
    echo "🔄 To retry after fixing issues:"
    echo "   ./deploy-to-github.sh"
    exit 1
fi
