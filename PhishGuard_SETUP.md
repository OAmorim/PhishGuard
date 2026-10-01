# PhishGuard - Setup Guide

This guide explains how to set up the PhishGuard project on a clean Windows machine using VS Code.

## 1. Recommended software

Install:

- Git
- Python 3.12.x
- Visual Studio Code
- VS Code Python extension

> Do not copy the old `.venv` folder from another PC. Create a new virtual environment on this machine.

## 2. Get the project

The safest option is to clone the current GitHub repository and keep the copy on the external drive only as a backup.

```powershell
git clone <GITHUB_REPOSITORY_URL>
cd PhishGuard
```

If you prefer to continue from the external-drive copy, first copy the project folder to the local disk and make sure it contains the `.git` folder.

You can confirm that Git recognises the repository with:

```powershell
git status
```

## 3. Confirm Python

```powershell
py -3.12 --version
```

You should see something similar to:

```text
Python 3.12.x
```

## 4. Create a new virtual environment

From the project root:

```powershell
py -3.12 -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

The terminal should then start with:

```text
(.venv)
```

## 5. Upgrade pip

```powershell
python -m pip install --upgrade pip
```

## 6. Install project dependencies

If the repository already contains `requirements.txt`:

```powershell
pip install -r requirements.txt
```

The current PhishGuard dependencies are expected to include:

```text
streamlit
pandas
scikit-learn
joblib
beautifulsoup4
tldextract
pytest
```

Ollama and LLM-related dependencies are not required yet.

## 7. Select the Python interpreter in VS Code

In VS Code:

1. Press `Ctrl + Shift + P`
2. Search for `Python: Select Interpreter`
3. Select the interpreter inside:

```text
PhishGuard\.venv\Scripts\python.exe
```

## 8. Run the tests

Use:

```powershell
python -m pytest .
```

This is the preferred test command for this project.

## 9. Run the Streamlit app

```powershell
streamlit run app.py
```

Streamlit should open the application in the browser, normally at:

```text
http://localhost:8501
```

## 10. Git workflow

Before continuing development:

```powershell
git status
git pull
```

After making changes:

```powershell
git add .
git status
git commit -m "your commit message"
git push
```

Always check `git status` before committing to make sure `.venv`, cache files, secrets, or unrelated files are not included.

## 11. Recommended `.gitignore`

The project should include at least:

```gitignore
# Python
__pycache__/
*.py[cod]

# Virtual environment
.venv/
venv/

# IDE
.vscode/
.idea/

# Model files
*.pkl
*.joblib

# Environment variables and secrets
.env
.env.*
secrets/
*.key
*.pem

# OS
.DS_Store
Thumbs.db

# Pytest
.pytest_cache/

# Streamlit
.streamlit/secrets.toml
```

## 12. Quick setup summary

For a clean PC, the usual sequence is:

```powershell
git clone <GITHUB_REPOSITORY_URL>
cd PhishGuard

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt

python -m pytest .
streamlit run app.py
```

## Notes

- Use the GitHub repository as the main source of truth.
- Keep the external-drive copy as a backup until the new setup is confirmed working.
- Do not reuse a virtual environment copied from the old PC.
- Do not commit API keys, passwords, tokens, real private emails, or other sensitive data.
