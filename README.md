# 🛡️ SIEM Log Analyzer with Threat Scoring

SIEM Log Analyzer with Threat Scoring is an advanced SIEM (Security Information and Event Management) tool built using Python and Streamlit. It empowers cybersecurity analysts and system administrators to analyze log files, detect anomalies, classify threat severity, and generate detailed PDF reports with visualizations.

---


## 📁 Project Structure

```
SIEM-Log-Analyzer-with-Threat-Scoring/
│
├── app.py               # Main Streamlit Application
├── README.md            # This file
```

---

## 🚀 Features

- 🔍 **Log Analysis with Threat Detection**
  - Scans uploaded log files for multiple threat patterns using regular expressions.
  - Identifies threats like Malware, Phishing, Unauthorized Access, Data Leakage, File Tampering, etc.
  - Classifies threats based on severity: Low, Medium, High, Critical.

- 🧠 **Anomaly Detection with Machine Learning**
  - Uses Isolation Forest to detect outlier IPs based on log behavior.
  - Identifies potentially malicious or suspicious IPs.

- 📊 **Data Visualization**
  - Generates **Bar Charts** and **Pie Charts** of detected threat frequencies.
  - Interactive visual summary of threat distribution.

- 🕵️ **Session Timeline & Log Details**
  - Tracks IP sessions and log line lengths.
  - Displays matched threat lines with activity type and severity.

- 📄 **PDF Report Export**
  - Exports a complete summary including:
    - Threat overview
    - Matched entries
    - Pie & bar graphs
    - Severity insights and remedies

- 📡 **Real-Time Log Simulation**
  - Simulates a live feed of incoming logs with threat detection.

---

## 🧠 Threat Categories & Remedies

| Threat Category      | Example Patterns                                  | Suggested Remedy                                                                 |
|----------------------|---------------------------------------------------|----------------------------------------------------------------------------------|
| Malware              | malware, trojan, ransomware                       | Antivirus scan, isolate systems, update software                                |
| Phishing             | phishing, spear phishing, fraudulent email        | Train users, enhance email filtering, report attempts                           |
| Unauthorized Access  | login failure, access denied                      | Reset credentials, enable MFA, monitor login history                            |
| Security Breach      | intrusion detected, unauthorized entry            | Disconnect affected systems, investigate, notify stakeholders                   |
| File Tampering       | unauthorized file modification                    | Restore from backup, audit logs, set file permissions                           |
| Advanced Malware     | rootkit, zero-day, APT                            | Deploy EDR tools, patch systems, perform forensic scans                         |
| Data Leakage         | data exfiltration, information leak               | Apply DLP, review access policies, audit logs                                   |

---

## 📦 Installation

### 🔧 Prerequisites

- Python 3.12
- pip

### 📥 Clone the Repository

```bash
git clone https://github.com/yourusername/SIEM-Log-Analyzer-with-Threat-Scoring.git
cd SIEM-Log-Analyzer-with-Threat-Scoring
```

### 📦 Install Dependencies

```bash
pip install streamlit pandas matplotlib numpy scikit-learn fpdf Pillow
```

### 🚀 Running the Application

```bash
streamlit run app.py
```
- Then, open your browser at http://localhost:8501
  
---

## 🧪 How It Works

1. Upload Log File (.log):

- The analyzer scans each line using regex for threat patterns.
- Computes a threat score and categorizes each activity.
- Logs are matched to IPs and threat types.

2. Anomaly Detection:

- Uses encoded IP and log line lengths as features.
- Detects IPs that deviate significantly from normal patterns.

3. Visualizations:

- Bar and Pie charts show threat type frequencies.
- Sample matched logs are displayed with severity.

4. PDF Export:

- Automatically embeds summary, logs, and charts into a downloadable PDF.

---
