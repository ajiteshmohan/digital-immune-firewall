# Digital Immune Firewall

A full-stack cybersecurity project inspired by biological immune systems.

## Overview
This project simulates a Digital Immune Firewall for hospital and critical
network environments. It monitors network activity, detects anomalies,
and visualizes threats using a web-based dashboard.

The frontend interface is hosted using GitHub Pages.
The backend firewall engine runs locally due to system-level permissions
required for packet capture.

## Tech Stack
- Backend: Node.js, Express, WebSocket, pcap
- Frontend: HTML, Tailwind CSS, JavaScript
- Detection: Rule-based and anomaly detection
- Storage: JSON files

## Project Structure

digital-immune-firewall/
├── index.html
├── assets/
│   └── logo.png
├── server.js
├── hospitalports.json
├── blacklist.json
├── public/
└── README.md

## Running the Project

### Frontend
The frontend UI can be accessed via GitHub Pages:

https://your-username.github.io/digital-immune-firewall/

### Backend
To run the backend locally:

npm install  
node server.js  

Then open:

http://localhost:8080

## Note
GitHub Pages supports only static frontend files.
Backend services such as packet capture cannot be deployed online.

## Author
CODEPLAY Team — 2025
