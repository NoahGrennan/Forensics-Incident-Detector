# Forensics-Incident-Detector
IT 360 Project

Forensics Incident Detector

Overview:
A Python-based incident detection tool for collecting logs, hashing key files, 
and generating HTML & JSON reports for forensic analysis.
Designed for quick incident response and digital forensics collection.
It automatically gathers logs, hashes important file systems, detects suspicious patterns, and produces a formatted output that an analyst can review.

This tool is made for:
-Learning DFIR
-SOC analysis performing quick triage
-Anyone testing brute-force attacks

Commands in bash
python3 incidetector.py

help: python3  incidetector.py --help
analize ssh logs: python3 incidetector.py --ssh
full report: python3 incidetector.py --full

Clone respiratory in bash
git clone https://github.com/NoahGrennan/Forensics-Incident-Detector.git

Navigate to the folder
cd Forensics-Incident-Detector/src

If needed to make it executable
chmod +x incidetector.py

Running the tool's basic syntax
python3 incidetector.py

Running tool with higher permissions(sudo) --soem logs require root to collect eg. /var/log/auth.log

Output files are saved in /output/
Can update the tool using "git pull"



