# 🛡️ PurpleOps: C2 Framework with Detection Suite

> A **Python & Go-based Purple Teaming Framework** that enables offensive command-and-control operations via GitHub issues and defends against malicious C2 agents using YARA, VirusTotal, and process behavior monitoring.

---

## 📁 Project Structure

```bash
PurpleOps/
│
├── agent.go                # Stealth C2 agent (written in Go)
├── app.py                 # Flask-based C2 command panel (Python)
├── countermeasure.py      # C2 detection and response suite
├── c2_rules.yar           # YARA signatures for known C2 patterns
├── requirements.txt       # Python dependencies
└── templates/index.html   # UI for command submission (optional)
```

---

## 🚀 Features

### ✅ Command & Control (C2) System

- Uses **GitHub Issues & Comments** as a covert C2 channel.
- Written in Go for portability on Windows targets.
- Hides console window and self-monitors via Windows Job Objects.
- Executes remote shell commands and posts results back to GitHub.

### ✅ C2 Detection & Response Suite

- Detects active C2 agents using **YARA**, process scans, and command-line indicators.
- Integrates **VirusTotal API** for file-based AV engine analysis.
- Offers real-time **remediation** (kill & delete C2 processes/files).

---

## 🧰 Installation

### 🔧 1. Clone the Repository

```bash
git clone https://github.com/Akilan-kj/Purpleops-C2-framework-with-Detection-suite.git
cd Purpleops-C2-framework-with-Detection-suite
```

### 🐍 2. Install Python Requirements

```bash
pip install -r requirements.txt
```

### 🛠️ 3. Edit Secrets (Important)

Update the following files with **your GitHub Token and Repo**:

- `agent.go`:

```go
const (
    githubToken = "<your_token>"
    repoName    = "your-username/your-repo"
)
```

- `app.py`:

```python
GITHUB_TOKEN = "<your_token>"
GITHUB_REPO  = "your-username/your-repo"
```

---

## ⚙️ Usage

### 1️⃣ Run the Flask C2 Panel

```bash
python app.py
```

Then visit: [http://localhost:5000](http://localhost:5000)

- Submit commands to connected agents
- View agent details and command history

---

### 2️⃣ Build & Run the Go Agent (Target system)

#### ✅ Build (on Linux or Windows)

```bash
go build -ldflags="-H windowsgui" -o agent.exe agent.go
```

> ⚠️ Important: This is a **stealth agent**. Run only in test environments or with proper consent.

---

### 3️⃣ Use the Detection Suite

```bash
python countermeasure.py
```

#### Menu Options:
1. Detect C2 Agent (via YARA + behavior)
2. Deep Scan with VirusTotal API
3. Eradicate detected C2 processes & files
4. Exit

---

## 🔬 How It Works (Detailed)

### 🟣 Agent (`agent.go`)

- Registers to GitHub by opening a new **Issue**.
- Constantly polls issue comments for commands.
- Executes commands silently using `cmd.exe`.
- Sends results back as a **comment** to the issue.

### 🟣 Command Panel (`app.py`)

- Flask API serves:
  - Agent list from issues
  - Command submission (POST to issue comment)
  - Execution history
- Uses GitHub REST API under the hood.

### 🟢 Detection Module (`countermeasure.py`)

- Scans running processes with:
  - `yara` rules (`c2_rules.yar`)
  - Known suspicious keywords (like `api.github.com`)
- Verifies files using **VirusTotal hash lookup**.
- Terminates and removes flagged C2 processes/files.

---

## 📊 Sample YARA Rule

```yara
rule GitHubC2
{
    strings:
        $a = "https://api.github.com"
    condition:
        $a
}
```

Place rules in `c2_rules.yar`.

---

## 🧪 VirusTotal API Integration

This feature uses file **hash lookup**, not uploads:

- Uses SHA-256 of suspected file
- Queries VirusTotal for analysis
- Prints AV engine verdicts in color-coded table

---

## 🔐 Security Note

⚠️ Avoid committing real secrets.  
Use a `.env` file and `os.environ` if needed for tokens.

---

## ✅ Requirements

- Python 3.7+
- Go 1.17+
- GitHub Personal Access Token with `repo` scope
- VirusTotal API Key (free key available via registration)

---

## 📜 License

This project is for **educational and authorized use only**.  
You must not deploy this on any system you do not own or have permission to test.
