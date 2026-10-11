# Wave Watcher: V1.0 (Operation: Static Shift)

An interactive, terminal-based Wi-Fi Intrusion Detection System (IDS) engine built with Python and Scapy to monitor, analyze, and detect wireless threats in real time.

> **Project Nexus Suite:** Wave Watcher is an official sub-project developed and maintained under the **Project Nexus**



## Run Locally

### Linux
> ⚠️ **OS Compatibility Notice:** Wave Watcher relies on raw socket manipulation and 802.11 monitor mode wireless frame extraction. Therefore, this tool exclusively operates on Linux systems with compatible wireless network interface controllers (NICs). Windows and macOS are not supported.

```bash
# Clone the repository and navigate into it
cd wave-watcher

# Create a virtual environment
python3 -m venv .Wave_Watcher --system-site-packages

# Activate the virtual environment
source .Wave_Watcher/bin/activate

# Install dependencies
pip install -r requirements.txt

# Deactivate/exit from the virtual environment
deactivate

# Create a convenient execution script
nano Wave_Watcher_Run.sh

#Paste the following code inside Wave_Watcher_Run.sh:
#!/bin/bash
./.Wave_Watcher/bin/python3 Wave_Watcher.py "$@"

#(Save and exit the editor)

#Make the script executable and run the IDS engine:
chmod +x Wave_Watcher_Run.sh

# use the below command to run the program without the need to active the virtual environment each time
./Wave_Watcher_Run.sh
```
# Files
- Wave_Watcher_V1.py – Core application engine containing the custom terminal user interface (TUI), wireless packet parsing logic, threat signature detection, and real-time alert orchestrator.

- requirements.txt – List of external Python package dependencies required to run the tool.

- Audio/ – Project directory containing pre-recorded audio alert samples executed dynamically during detected threat events.

# Project Features
- Wave Watcher (Operation: Static Shift) is a lightweight, open-source command-line utility designed to provide network administrators with real-time defensive monitoring of 802.11 wireless space. By interfacing directly with raw socket captures and low-level frame streams via Scapy, the utility automates threat signature evaluation, rogue access point discovery, and packet anomaly tracking inside a sleek, color-coded ANSI terminal layer.

- Real-Time Wireless IDS: Continuously captures and parses raw 802.11 management, control, and data frames across active wireless channels to detect live network anomalies.

- Acoustic Alert System: Features an integrated audio-based warning engine that plays distinct, pre-recorded audio alerts directly upon identifying high-risk threat signatures.

- Dynamic Sensitivity & Threshold Adjustment: Features customizable threat tolerance thresholds directly within the codebase, allowing the detection engine to dynamically adapt its alert triggers based on target environment noise and security posture.

- Deauthentication & Disassociation Defense: Flags high-frequency deauthentication frame bursts in real time, alerting operators to active denial-of-service (DoS) and wireless disruption attempts.

- Rogue AP & Spoofing Detection: Analyzes beacon frame intervals, BSSID parameters, and SSID broad-casting behaviors to identify unauthorized access points and potential evil-twin deployments.

- Operational Threat Logging: Automatically structures security event telemetry and incident flags into clean, persistent local log files for post-event forensic auditing and security review.
