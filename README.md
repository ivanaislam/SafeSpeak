# SafeSpeak X

<p align="center">
  <img src="docs/images/case-tracking.jpeg" alt="SafeSpeak X secure case tracking" width="760">
</p>

<p align="center">
  <strong>A privacy-focused platform for anonymous incident reporting and secure case tracking.</strong>
</p>

## Overview

SafeSpeak X allows users to submit incident reports without exposing unnecessary personal information. The backend automatically redacts sensitive data, generates a private case code and passphrase, and provides a protected administrator dashboard for reviewing and managing reports.

## Main Features

- Anonymous incident submission
- Automatic PII redaction using spaCy and regular expressions
- Private case code and passphrase generation
- Secure case-status tracking
- Evidence attachment support
- Risk scoring and report categorization
- JWT-protected administrator dashboard
- Administrator login lockout and security-event monitoring
- Audit logs and administrator replies
- SQLite support for local development
- PostgreSQL support through an environment variable

## Project Preview

<p align="center">
  <img src="docs/images/anonymous-reporting.jpeg" alt="Anonymous incident reporting interface" width="31%">
  <img src="docs/images/case-tracking.jpeg" alt="Secure case tracking interface" width="31%">
  <img src="docs/images/privacy-redaction.jpeg" alt="Automatic privacy redaction interface" width="31%">
</p>

## Technology Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite or PostgreSQL
- spaCy
- JWT authentication
- HTML, CSS, and JavaScript

## Project Structure

```text
SafeSpeak-X/
├── backend/
│   ├── app/
│   │   └── main.py
│   ├── uploads/
│   │   └── .gitkeep
│   └── requirements.txt
├── docs/
│   └── images/
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── track.html
├── .env.example
├── .gitignore
└── README.md
```

## Run SafeSpeak X Locally

Run the project from the main `SafeSpeak-X` directory unless a section specifically says otherwise.

### Application URLs

After starting the server, open one of these URLs:

| Page | URL |
|---|---|
| Home page | <http://127.0.0.1:8000> |
| Submit report | <http://127.0.0.1:8000/submit> |
| Track case | <http://127.0.0.1:8000/track> |
| Administrator dashboard | <http://127.0.0.1:8000/admin> |
| API documentation | <http://127.0.0.1:8000/docs> |
| Health check | <http://127.0.0.1:8000/api/health> |

---

## Linux, Kali Linux, and Ubuntu

### 1. Install the required software

Open a terminal and run:

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv
```

Check the installations:

```bash
git --version
python3 --version
pip3 --version
```

### 2. Clone the repository

```bash
git clone https://github.com/Choity23/SafeSpeak-X.git
cd SafeSpeak-X
```

Check the project files and your current location:

```bash
ls -la
pwd
```

The path should end with:

```text
/SafeSpeak-X
```

Stay in the main project directory. Do not enter the `backend` directory for the standard setup commands.

### 3. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

After activation, `(venv)` should appear before the terminal prompt.

Example:

```text
(venv) kali@kali:~/SafeSpeak-X$
```

### 4. Upgrade pip

```bash
python -m pip install --upgrade pip
```

### 5. Install the Python dependencies

```bash
pip install -r backend/requirements.txt
python -m spacy download en_core_web_sm
```

Test the installed packages:

```bash
python -c "import fastapi, sqlalchemy, spacy; print('All dependencies installed successfully')"
```

Test the spaCy model:

```bash
python -c "import spacy; spacy.load('en_core_web_sm'); print('spaCy model is working')"
```

### 6. Create the environment file

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Open the file:

```bash
nano .env
```

Use values similar to these:

```env
SAFESPEAK_SECRET_KEY=replace-this-with-a-long-random-secret-key
SAFE_SPEAK_ADMIN_USERNAME=admin@example.com
SAFE_SPEAK_ADMIN_PASSWORD=ChangeThisPassword123
SAFESPEAK_DATABASE_URL=sqlite:///./backend/safespeak.db
SAFESPEAK_ALLOWED_ORIGINS=http://127.0.0.1:8000,http://localhost:8000
SAFESPEAK_NLP_MODEL=en_core_web_sm
```

Change these values before running the application:

- `SAFESPEAK_SECRET_KEY`
- `SAFE_SPEAK_ADMIN_USERNAME`
- `SAFE_SPEAK_ADMIN_PASSWORD`

You can generate a strong secret key with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

To save the file in Nano, press `Ctrl + O`, press `Enter`, and then press `Ctrl + X`.

Confirm that the file exists:

```bash
ls -la .env
```

### 7. Load the environment variables

```bash
set -a
source .env
set +a
```

Confirm that the administrator username was loaded:

```bash
echo "$SAFE_SPEAK_ADMIN_USERNAME"
```

### 8. Start the application

Make sure you are still in the main `SafeSpeak-X` directory:

```bash
pwd
```

Start the FastAPI server:

```bash
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

A successful start should include output similar to:

```text
Uvicorn running on http://127.0.0.1:8000
Application startup complete.
```

Keep this terminal open while using the application.

### 9. Open the application

Open <http://127.0.0.1:8000> in a browser.

Use the administrator username and password from your `.env` file to sign in to the administrator dashboard.

### 10. Stop the application

Press `Ctrl + C` in the terminal, then deactivate the virtual environment:

```bash
deactivate
```

### Run the project again on Linux

You do not need to reinstall the dependencies each time.

```bash
cd ~/SafeSpeak-X
source venv/bin/activate
set -a
source .env
set +a
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000>.

---

## Windows PowerShell

### 1. Install the required software

Install the following programs:

- Git
- Python 3.10 or newer
- pip

Install Git with `winget`:

```powershell
winget install --id Git.Git -e --source winget
```

Install Python with `winget`:

```powershell
winget install --id Python.Python.3.12 -e --source winget
```

Close PowerShell and open it again after installation.

Check the installations:

```powershell
git --version
python --version
pip --version
```

### 2. Clone the repository

Go to the Downloads directory:

```powershell
cd "$HOME\Downloads"
```

Clone the repository and enter the project directory:

```powershell
git clone https://github.com/Choity23/SafeSpeak-X.git
cd ".\SafeSpeak-X"
```

Check the files and current location:

```powershell
Get-ChildItem -Force
Get-Location
```

The path should end with:

```text
SafeSpeak-X
```

Stay in the main project directory. Do not enter the `backend` directory for the standard setup commands.

### 3. Create and activate a virtual environment

```powershell
python -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

After activation, `(venv)` should appear before the PowerShell prompt.

Example:

```text
(venv) PS C:\Users\User\Downloads\SafeSpeak-X>
```

### 4. Upgrade pip

```powershell
python -m pip install --upgrade pip
```

### 5. Install the Python dependencies

```powershell
pip install -r .\backend\requirements.txt
python -m spacy download en_core_web_sm
```

Test the installed packages:

```powershell
python -c "import fastapi, sqlalchemy, spacy; print('All dependencies installed successfully')"
```

Test the spaCy model:

```powershell
python -c "import spacy; spacy.load('en_core_web_sm'); print('spaCy model is working')"
```

### 6. Create the environment file

Copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

Open the file in Notepad:

```powershell
notepad .env
```

Use values similar to these:

```env
SAFESPEAK_SECRET_KEY=replace-this-with-a-long-random-secret-key
SAFE_SPEAK_ADMIN_USERNAME=admin@example.com
SAFE_SPEAK_ADMIN_PASSWORD=ChangeThisPassword123
SAFESPEAK_DATABASE_URL=sqlite:///./backend/safespeak.db
SAFESPEAK_ALLOWED_ORIGINS=http://127.0.0.1:8000,http://localhost:8000
SAFESPEAK_NLP_MODEL=en_core_web_sm
```

Change these values before running the application:

- `SAFESPEAK_SECRET_KEY`
- `SAFE_SPEAK_ADMIN_USERNAME`
- `SAFE_SPEAK_ADMIN_PASSWORD`

You can generate a strong secret key with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Save and close Notepad, then confirm that the file exists:

```powershell
Get-ChildItem -Force .env
```

### 7. Load the environment variables

PowerShell does not automatically load variables from `.env`. Run this complete command:

```powershell
Get-Content .env | ForEach-Object {
    $Line = $_.Trim()

    if ($Line -and -not $Line.StartsWith("#")) {
        $Name, $Value = $Line -split "=", 2

        if ($Name -and $Value) {
            Set-Item -Path "Env:$($Name.Trim())" -Value $Value.Trim()
        }
    }
}
```

Confirm that the administrator username was loaded:

```powershell
$env:SAFE_SPEAK_ADMIN_USERNAME
```

### 8. Start the application

Make sure you are in the main `SafeSpeak-X` directory:

```powershell
Get-Location
```

Start the FastAPI server:

```powershell
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

A successful start should include output similar to:

```text
Uvicorn running on http://127.0.0.1:8000
Application startup complete.
```

Keep PowerShell open while using the application.

### 9. Open the application

Open <http://127.0.0.1:8000> in a browser.

Use the administrator username and password from your `.env` file to sign in to the administrator dashboard.

### 10. Stop the application

Press `Ctrl + C` in PowerShell, then deactivate the virtual environment:

```powershell
deactivate
```

### Run the project again on Windows

You do not need to reinstall the dependencies each time.

```powershell
cd "$HOME\Downloads\SafeSpeak-X"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

Get-Content .env | ForEach-Object {
    $Line = $_.Trim()

    if ($Line -and -not $Line.StartsWith("#")) {
        $Name, $Value = $Line -split "=", 2

        if ($Name -and $Value) {
            Set-Item -Path "Env:$($Name.Trim())" -Value $Value.Trim()
        }
    }
}

python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000>.

---

## Important Path Rule

From the main project directory, use:

```bash
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Your current directory should be:

```text
SafeSpeak-X/
```

When you are already inside the `backend` directory, use:

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Do not run the following command from inside the `backend` directory:

```bash
python -m uvicorn backend.app.main:app
```

That command makes Python search for a path similar to:

```text
backend/backend/app/main.py
```

## Common Errors

### Requirements file not found

From the main project directory:

```bash
pip install -r backend/requirements.txt
```

From inside the `backend` directory:

```bash
pip install -r requirements.txt
```

### `.env.example` not found

Return to the main project directory:

```bash
cd ..
```

On Linux, check hidden files and copy the example file:

```bash
ls -la
cp .env.example .env
```

On Windows PowerShell:

```powershell
Get-ChildItem -Force
Copy-Item .env.example .env
```

### Virtual environment cannot be created on Linux

Install the `venv` package and try again:

```bash
sudo apt update
sudo apt install -y python3-venv
python3 -m venv venv
```

### PowerShell blocks virtual environment activation

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

This changes the execution policy only for the current PowerShell session.

### Uvicorn is not found

Make sure the virtual environment is active, then run:

```bash
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

### Port 8000 is already in use

Start the server on port `8001`:

```bash
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8001
```

Then open <http://127.0.0.1:8001>.

### spaCy model is missing

```bash
python -m spacy download en_core_web_sm
```

## Database

SafeSpeak X uses SQLite by default. The database file is created automatically at:

```text
backend/safespeak.db
```

You do not need to create the SQLite database manually.

For production deployments, set `SAFESPEAK_DATABASE_URL` to a PostgreSQL connection string.

## Security Notes

- Never upload the real `.env` file to GitHub.
- Never upload `backend/safespeak.db`.
- Never upload evidence files from `backend/uploads/`.
- Use a strong administrator password.
- Change the secret key before deployment.
- Use HTTPS for public deployments.
- Use PostgreSQL for production deployments.
- Review uploaded evidence before moving or sharing it.
- Keep dependencies updated and review security logs regularly.

## License

This project is intended for educational and research use. Add a `LICENSE` file before wider distribution or public reuse.
