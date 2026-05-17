# 🛡️ Guardian GPU: AI-Powered GPU Security & Monitoring

Guardian GPU is an advanced, real-time GPU monitoring and threat detection system. It leverages low-level system tracing and Machine Learning to detect, flag, and neutralize unauthorized GPU workloads (such as stealthy crypto-miners or malware) before they can drain system resources.

## ✨ Key Features

* **Real-Time GPU Monitoring:** Utilizes C++ and Windows Event Tracing (ETW) to capture precise, low-level metrics of GPU usage, memory allocation, and kernel execution.
* **AI Anomaly Detection:** Features a Python-based "Brain" that uses an **Isolation Forest** machine learning algorithm to analyze behavioral patterns and identify malicious or abnormal GPU spikes in real-time.
* **Automated Process Control:** Automatically intercepts and terminates unauthorized processes based on dynamic threat scoring, protecting hardware resources from abuse.
* **Smart Whitelisting System:** Allows administrators to securely whitelist trusted applications, ensuring legitimate heavy workloads (like rendering or gaming) are not interrupted.
* **Secure Web Dashboard:** A responsive, modern web interface with built-in Two-Factor Authentication (2FA) and session management for reviewing logs, managing processes, and monitoring live system health.

## 🏗️ System Architecture

The project is built using a robust, multi-tier architecture:

1. **Sensor Node (C++/CUDA):** Interfaces directly with the OS and GPU hardware to collect high-fidelity performance metrics.
2. **Analysis Engine (Python):** Processes telemetry data, evaluates it against the trained Isolation Forest model, and updates the knowledge bank.
3. **Command & Control API (Python/Flask):** Handles secure communication between the monitoring backend, the SQLite database, and the frontend dashboard.
4. **Web Frontend (HTML/CSS/JS):** Provides an intuitive administrative console.

## 🛠️ Technology Stack

* **Low-Level Monitor:** C++, CUDA, Windows ETW (Event Tracing for Windows)
* **Backend & AI Engine:** Python, Scikit-Learn (Isolation Forest), Pandas, NumPy
* **API & Security:** Flask, JWT, Two-Factor Authentication (2FA)
* **Database:** SQLite (`guardian.db`)
* **Frontend:** HTML5, CSS3, Vanilla JavaScript

## 🚀 Installation & Setup

### Prerequisites
* Windows OS (due to ETW dependencies)
* Python 3.x
* C++ Build Tools & CUDA Toolkit

### Steps to Run
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/Guardian-GPU.git
   cd Guardian-GPU
