@echo off
REM PII Detector - GitHub Deployment Script for Windows
REM This script will initialize git, add files, and push to GitHub

echo 🚀 Starting GitHub deployment for PII Detector...

REM Repository URL
set REPO_URL=https://github.com/nabcom-agent/PII-detector.git

REM Check if git is installed
git --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git is not installed. Please install Git first.
    pause
    exit /b 1
)

echo [INFO] Git is available. Proceeding with deployment...

REM Navigate to project directory
cd /d "%~dp0"

REM Initialize git repository if not already done
if not exist ".git" (
    echo [INFO] Initializing Git repository...
    git init
    echo [SUCCESS] Git repository initialized
) else (
    echo [INFO] Git repository already exists
)

REM Add remote origin if not already added
git remote get-url origin >nul 2>&1
if errorlevel 1 (
    echo [INFO] Adding remote origin...
    git remote add origin %REPO_URL%
    echo [SUCCESS] Remote origin added: %REPO_URL%
) else (
    echo [INFO] Remote origin already exists
    git remote set-url origin %REPO_URL%
    echo [SUCCESS] Remote origin URL updated
)

REM Create/switch to main branch
git checkout -b main 2>nul || git checkout main 2>nul

REM Remove zip file if exists
if exist "pii-encryption-tool.zip.zip" (
    echo [INFO] Removing zip file from repository...
    git rm --cached pii-encryption-tool.zip.zip 2>nul
)

REM Stage all files
echo [INFO] Staging files for commit...
git add .

REM Check if there are changes to commit
git diff --staged --quiet
if errorlevel 1 (
    echo [INFO] Creating commit...
    git commit -m "Initial commit: PII Detection & Encryption Tool - Comprehensive privacy and security solution with 25+ PII patterns, Web Crypto API integration, and enterprise-ready features"
    echo [SUCCESS] Commit created successfully
) else (
    echo [WARNING] No changes to commit. Repository is up to date.
)

REM Push to GitHub
echo [INFO] Pushing to GitHub repository...
git push -u origin main
if errorlevel 1 (
    echo [ERROR] Failed to push to GitHub.
    echo This might be due to:
    echo   • Authentication required (use personal access token)
    echo   • Repository already has content
    echo   • Network connectivity issues
    echo.
    echo To resolve authentication issues:
    echo   1. Generate a Personal Access Token at: https://github.com/settings/tokens
    echo   2. Use token as password when prompted
    pause
    exit /b 1
) else (
    echo [SUCCESS] Successfully pushed to GitHub! 🎉
    echo.
    echo 🌐 Your repository is now available at:
    echo    %REPO_URL%
    echo.
    echo 🔧 Next steps:
    echo    1. Visit your GitHub repository
    echo    2. Enable GitHub Pages for live demo
    echo    3. Add repository description and topics
    echo.
    echo [SUCCESS] Deployment completed successfully! ✅
)

pause
