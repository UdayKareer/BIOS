# 🛡️ GhostGuard — Software Supply Chain Sentinel
> **BIOS Hackathon (TIET / CSED) — Problem #10: Supply Chain Guardian**  
> **Global Mandate:** UN SDG 16.4 (Secure International Software Supply Chains)  
> **Live Systems:** Frontend on `http://localhost:3000` | Backend on `http://localhost:8000`

---

## ⚡ The Core Problem & Our Breakthrough

Modern developers run `pip install` or `npm install` dozens of times a day. Attackers exploit this by publishing **typosquats** (e.g., `reqeusts` instead of `requests`) that harbor **obfuscated base64 stagers** in `setup.py` or `postinstall.js`. The moment a developer presses Enter:
- `~/.ssh/id_rsa` and AWS/OpenAI `.env` secrets are read from disk.
- Stolen credentials are transmitted to an overseas C2 beacon in under **0.30 seconds**.
- The developer's machine is permanently compromised before their code even imports the library.

Traditional linters cry wolf on hundreds of safe libraries, causing alert fatigue. **GhostGuard** solves this with a **zero-tolerance, zero-wolf multi-layered defensive pipeline**:

```
[ Developer Input ] 
       ↓
1. Boarding Pass Check ──► Typosquat Radar (Damerau-Levenshtein <= 2 & Cyrillic Homoglyphs)
       ↓
2. Baggage X-Ray       ──► Real AST Static Analysis & In-Memory Base64/Hex De-Obfuscation
       ↓
3. Detonation Chamber  ──► 0.30s Micro-Sandbox Interceptor (Terminates secret exfiltration)
       ↓
4. Customs Clearance   ──► Zero-Wolf Engine + CycloneDX 1.5 SBOM + Pip Hash Lockdown
```

---

## 🚀 Key Features Built & Demonstrated

### 1. 📁 Whole-Project Manifest Auditor (`POST /api/scan-manifest`)
- Pasting a full `requirements.txt` or `package.json` audits all dependencies simultaneously.
- Flags the exact poisoned dependency among safe packages.
- Calculates an **Aggregated Project Security Score** (e.g., `28/100` 🔴 CRITICAL RISK).
- 1-Click downloads a hardened manifest with cryptographic SHA-256 hashes (`--require-hashes`) and an authoritative CycloneDX v1.5 SBOM.

### 2. 🧪 Interactive Virtual Detonation Chamber with Playback & Web Audio
- Traces real-time container syscalls from `0.00s` to `0.30s`.
- Interactive `Play`, `Pause`, `Reset`, and `Step` controls with an animated timeline scrubber.
- Discrete Web Audio synthesizer providing realistic auditory cues on milestone events and a distinct SIGKILL termination alert.

### 3. 🌐 Topological Threat Vector & Syscall Trapping Map (SVG)
- Live SVG diagram visualizing the compromised dependency's path from local developer shell to sensitive keystores (`~/.ssh/id_rsa`, `~/.env`) and rogue C2 server (`185.220.101.4:443`).
- Dynamic glowing shield turns red on interception or green on safe canonical libraries.

### 4. 🐺 Zero-Wolf False-Positive Suppression
- Solves Problem #10's strict criteria: *"without crying wolf on safe packages"*.
- Canonical packages (e.g. `requests`, `lodash`) with 10+ year release histories and verified PSF/npm cryptographic keyrings are verified with a 100/100 trust score.

### 5. 🎙️ 1-Click "Judge Presentation Mode"
- Built-in floating walkthrough drawer tailored for a 1st-year computer science presenter.
- 1-Click buttons to trigger the attack scenario, the safe zero-wolf proof, the whole-project audit, and display the 30-second speaking cue card.

---

## 🏃 Quick Start Guide

### Start the Backend (Port 8000)
```powershell
cd BACKEND
.\.venv\Scripts\uvicorn.exe main:app --host 127.0.0.1 --port 8000
```
API Documentation available at: `http://localhost:8000/docs`

### Start the Frontend (Port 3000)
```powershell
python -m http.server 3000 --directory "FRONTEND"
```
Open your browser at: `http://localhost:3000`

---

## 🎯 60-Second Presentation Pitch for Hackathon Judges

> *"Hello Judges! GhostGuard acts like an airport security scanner for code dependencies before they touch your computer.*
>
> 1. *First, we check the **boarding pass**: our Damerau-Levenshtein radar catches typosquats like `reqeusts` altering a single letter.*
> 2. *Second, we **X-ray the baggage**: our AST engine disassembles hidden Base64 stagers without running them.*
> 3. *Third, we **detonate in a blast chamber**: an isolated 0.30-second micro-sandbox traps unauthorized attempts to read `~/.ssh` or connect to rogue C2 servers, issuing a kernel SIGKILL before any secret escapes.*
> 4. *And most importantly, we **never cry wolf**: our provenance engine checks 13-year keyring trust so canonical packages like `requests` pass with 100/100.*
> 5. *Finally, we audit entire project files (`requirements.txt`) in one click, generating CycloneDX 1.5 SBOMs and zero-trust hash lockfiles compliant with UN SDG 16.4."*
