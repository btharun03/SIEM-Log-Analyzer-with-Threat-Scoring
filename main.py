# CyberSentinel Pro: Enhanced Threat-Aware Log Analyzer with Advanced SIEM Features
# Features: Severity classification, real-time log monitoring, session timeline, PDF export with bar graph & pie chart, and anomaly detection

import streamlit as st
import re
import matplotlib.pyplot as plt
from collections import defaultdict
import json
import os
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import tempfile
from fpdf import FPDF
from PIL import Image
import time

patterns = {
    'malware': re.compile(r'malware|virus|trojan|ransomware', re.IGNORECASE),
    'file_tampering': re.compile(r'file tampering|unauthorized file modification', re.IGNORECASE),
    'unauthorized_access': re.compile(r'unauthorized access|login failure|invalid login|access denied', re.IGNORECASE),
    'security_breach': re.compile(r'security breach|data breach|intrusion detected|unauthorized entry', re.IGNORECASE),
    'advanced_malware': re.compile(r'zero-day|advanced persistent threat|rootkit', re.IGNORECASE),
    'phishing': re.compile(r'phishing|spear phishing|fraudulent email', re.IGNORECASE),
    'data_leakage': re.compile(r'data leakage|data exfiltration|information leak', re.IGNORECASE)
}

remedies = {
    'malware': "Run a full antivirus scan, isolate systems, update software.",
    'file_tampering': "Restore from backup, check file permissions, audit logs.",
    'unauthorized_access': "Reset credentials, enable MFA, monitor login history.",
    'security_breach': "Disconnect system, investigate, notify stakeholders.",
    'advanced_malware': "Deploy EDR tools, perform forensic scan, patch systems.",
    'phishing': "Train users, improve email filters, report attempts.",
    'data_leakage': "Audit access logs, apply DLP tools, review policy."
}

severity_map = {
    'unauthorized_access': 'Medium',
    'malware': 'High',
    'data_leakage': 'High',
    'file_tampering': 'Medium',
    'phishing': 'High',
    'security_breach': 'High',
    'advanced_malware': 'Critical'
}

anomaly_model = IsolationForest(contamination=0.05)

@st.cache_data
def load_patterns():
    return patterns, remedies

def analyze_log_file(lines):
    suspicious_activity = defaultdict(int)
    total_lines = len(lines)
    ip_counter = defaultdict(int)
    threat_score = 0
    details = []
    session_data = []

    for line in lines:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        ip = ip_match.group() if ip_match else "Unknown"
        session_data.append([ip, len(line)])

        for activity, pattern in patterns.items():
            if pattern.search(line):
                suspicious_activity[activity] += 1
                threat_score += 10
                severity = severity_map.get(activity, 'Low')
                details.append((activity, line.strip(), severity))

        if ip_match:
            ip_counter[ip] += 1
            if 'failed' in line.lower():
                threat_score += 2

    return suspicious_activity, total_lines, threat_score, ip_counter, details, session_data

def detect_anomalies(session_data):
    df = pd.DataFrame(session_data, columns=['ip', 'log_length'])
    df['encoded_ip'] = df['ip'].astype('category').cat.codes
    features = df[['encoded_ip', 'log_length']]
    preds = anomaly_model.fit_predict(features)
    df['anomaly'] = preds
    anomalies = df[df['anomaly'] == -1]['ip'].value_counts().to_dict()
    return anomalies

def export_pdf_report(summary, details, suspicious_activity):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Bar chart
    fig1, ax1 = plt.subplots()
    ax1.bar(suspicious_activity.keys(), suspicious_activity.values(), color='red')
    ax1.set_ylabel("Occurrences")
    ax1.set_title("Threats Detected - Bar Chart")
    bar_chart_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
    fig1.savefig(bar_chart_path)
    plt.close(fig1)

    # Pie chart
    fig2, ax2 = plt.subplots()
    ax2.pie(suspicious_activity.values(), labels=suspicious_activity.keys(), autopct='%1.1f%%', startangle=90)
    ax2.set_title("Threats Distribution - Pie Chart")
    pie_chart_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
    fig2.savefig(pie_chart_path)
    plt.close(fig2)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Threat-Aware Log Analyzer Report", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Analysis Timestamp: {now}", ln=True)

    for key, value in summary.items():
        pdf.cell(200, 10, txt=f"{key}: {value}", ln=True)

    pdf.cell(200, 10, txt="\nMatched Entries:", ln=True)
    for act, log, sev in details[:30]:
        safe_log = log.encode('ascii', 'ignore').decode()
        pdf.multi_cell(0, 10, txt=f"[{sev}] {act.upper()} -> {safe_log}")

    pdf.image(bar_chart_path, x=10, y=None, w=180)
    pdf.image(pie_chart_path, x=10, y=None, w=180)

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    pdf.output(tmp_file.name)
    return tmp_file.name

def main():
    st.set_page_config(page_title="Log Analyzer", layout="wide")
    st.title("🛡️ SIEM Log Analyzer")
    st.write("Upload or monitor logs to detect security threats with severity, scoring, and anomaly detection.")

    load_patterns()

    tab1, tab2 = st.tabs(["📁 Upload Log File", "📡 Real-Time Monitor"])

    with tab1:
        uploaded_file = st.file_uploader("Choose a .log file", type="log")
        if uploaded_file:
            lines = uploaded_file.read().decode('utf-8').splitlines()
            suspicious_activity, total_lines, threat_score, ip_counter, details, session_data = analyze_log_file(lines)
            anomalies = detect_anomalies(session_data)

            st.subheader("🔍 Analysis Summary")
            st.write(f"**Total lines processed:** {total_lines}")
            st.write(f"**Threat Score:** {threat_score} / {total_lines * 10}")

            st.subheader("🚨 Detected Threats")
            for activity, count in suspicious_activity.items():
                st.markdown(f"**{activity}** ({severity_map.get(activity)}): {count}")
                st.markdown(f"> _Remedy_: {remedies.get(activity)}")

            if anomalies:
                st.subheader("⚠️ Anomalous IPs Detected")
                for ip, count in anomalies.items():
                    st.warning(f"{ip} - {count} anomalous events")

            st.subheader("📊 Threat Frequency Chart")
            fig, ax = plt.subplots()
            ax.bar(suspicious_activity.keys(), suspicious_activity.values(), color='red')
            ax.set_ylabel("Occurrences")
            ax.set_title("Threats Detected")
            st.pyplot(fig)

            st.subheader("🥧 Threat Distribution Pie Chart")
            fig2, ax2 = plt.subplots()
            ax2.pie(suspicious_activity.values(), labels=suspicious_activity.keys(), autopct='%1.1f%%')
            ax2.set_title("Threats Distribution")
            st.pyplot(fig2)

            st.subheader("📜 Sample Matched Entries")
            for act, log, sev in details[:20]:
                st.text(f"[{sev}] {act.upper()} -> {log}")

            st.subheader("📥 Download Report")
            summary = {
                "Total lines": total_lines,
                "Threat Score": threat_score,
                "Unique IPs": len(ip_counter),
                "Anomalous IPs": len(anomalies)
            }
            if st.button("Export PDF Report"):
                pdf_path = export_pdf_report(summary, details, suspicious_activity)
                with open(pdf_path, "rb") as f:
                    st.download_button("Download PDF", f, file_name="cybersentinel_report.pdf")

    with tab2:
        st.write("📡 Real-Time Log Monitoring Initialized")
        st.info("Simulated live feed will refresh every few seconds.")
        demo_logs = [
            "Jun 21 10:01:00 ERROR Unauthorized access attempt detected from IP: 192.168.1.100",
            "Jun 21 10:05:00 ERROR Malware detected in system",
            "Jun 21 10:09:00 ALERT Data leakage event triggered",
            "Jun 21 10:15:00 WARNING Phishing email identified",
        ]
        placeholder = st.empty()
        for i in range(4):
            time.sleep(2)
            placeholder.info(demo_logs[i % len(demo_logs)])

if __name__ == '__main__':
    main()
