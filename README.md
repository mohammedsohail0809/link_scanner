# 🛡️ Link Scanner

A robust, multi-engine URL security scanner that analyzes links for phishing, malware, and suspicious patterns. It doesn't just look at a URL; it dissects it using industrial-grade security intelligence.

## ✨ Features

- **Redirection Tracing**: Follows deep redirect chains (up to 10 hops) to find the final hidden destination.
- **Multi-Engine Intelligence**:
  - **VirusTotal**: Aggregated results from 70+ antivirus engines.
  - **Google Safe Browsing**: Accesses the world's most comprehensive threat database.
- **Domain Identity (WHOIS)**: Uncovers the truth behind a domain—who registered it, when, and how long they've been around.
- **Geographic Analysis**: Resolves server IPs and maps their physical location to spot suspicious hosting regions.
- **Heuristic Engine**: Detects "sneaky" patterns like raw IP usage, lookalike (homograph) domains, and keyword-stuffed URLs.
- **Dynamic UI**: Real-time visual feedback with risk-based background gradients (Safe, Suspicious, Malicious).

## 🧠 The Security Core

### 🕵️ VirusTotal Integration
We leverage the **VirusTotal v3 API** to consult over 70 security vendors simultaneously. Instead of relying on one opinion, Link Scanner gets a consensus. If even a few engines flag a URL, our scoring system raises the alarm. It’s like having a room full of security experts auditing your link in seconds.

### 🛡️ Google Safe Browsing
Link Scanner integrates with **Google's Safe Browsing API**, the same technology that protects billions of Chrome and Android users. It checks URLs against Google's constantly updated lists of unsafe web resources (phishing, malware, and unwanted software). If Google has seen it before, you'll know.

### 🔍 WHOIS & Domain Aging
Cybercriminals often use "burnable" domains—registered just hours before an attack. Our **WHOIS module** calculates the exact age of a domain.
- **Under 7 days?** High Alert.
- **Under 30 days?** Proceed with caution.
- **Unregistered?** Major Red Flag.
By identifying the registrar and creation date, we help you spot a legitimate site vs. a "pop-up" phishing page.

## 🚀 Getting Started

### 1. Prerequisites
- [Node.js](https://nodejs.org/) (v18+)
- [VirusTotal API Key](https://www.virustotal.com/) (Free tier works great!)
- [Google Safe Browsing API Key](https://console.cloud.google.com/)

### 2. Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/link-scanner.git
   cd link-scanner
   ```
2. Install dependencies:
   ```bash
   npm install
   ```

### 3. Configuration
Create a `.env` file in the root directory and add your keys:
```env
GOOGLE_SAFE_BROWSING_KEY=your_google_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

### 4. Launch
```bash
npm start
```
Open `http://localhost:3000` and start scanning!

## 🛠️ Technical Stack
- **Backend**: Node.js & Express
- **Intelligence**: VirusTotal API, Google Safe Browsing API, IP-API
- **Tools**: `whois` (Node module), `node-fetch`
- **Frontend**: Vanilla JS with modern CSS Gradients & Animations

## ⚖️ License
This project is licensed under the ISC License.
