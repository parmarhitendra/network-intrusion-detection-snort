# Network Intrusion Detection System (NIDS) Using Snort
A comprehensive hands-on cybersecurity training project focused on building and configuring a Network Intrusion Detection System using Snort. This 3-month progressive training program guides learners from foundational concepts to advanced alert management and reporting.

## 📋 Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Project Timeline](#project-timeline)
- [Project Structure](#project-structure)
- [Usage](#usage)
- [Learning Outcomes](#learning-outcomes)
- [Deliverables](#deliverables)
- [Contributing](#contributing)
- [Resources](#resources)
- [License](#license)

## 🎯 Overview

This project provides a structured approach to learning network intrusion detection through practical implementation of Snort IDS. Participants will gain hands-on experience in:

- Installing and configuring Snort on Linux
- Monitoring network traffic in real-time
- Simulating various network attacks
- Writing custom detection rules
- Managing alerts and reducing false positives
- Implementing advanced logging and visualization

## 🚀 Problem Statement

Build and configure a working Network Intrusion Detection System using Snort, capable of detecting and logging suspicious network activity. Learners will simulate attacks, write custom rules, and implement alerting mechanisms to develop practical cybersecurity skills.

## ✨ Features

- **Real-time Network Monitoring**: Monitor live network traffic and detect suspicious activities
- **Custom Rule Development**: Create and implement custom Snort rules for specific threats
- **Attack Simulation**: Simulate various attack scenarios including:
  - Ping floods
  - TCP port scans
  - SSH brute force attacks
- **Alert Management**: Multi-output logging and notification systems
- **Performance Optimization**: Rule tuning and preprocessor configuration
- **Visualization**: Dashboard implementation using ELK stack (optional)

## 📦 Prerequisites

### Hardware Requirements
- Minimum 4GB RAM (8GB recommended)
- 20GB free disk space
- Network interface card

### Software Requirements
- Linux OS (Ubuntu 20.04+ or Kali Linux recommended)
- Basic command-line knowledge
- Text editor (vim, nano, or VS Code)

### Knowledge Prerequisites
- Basic networking concepts (TCP/IP, ports, protocols)
- Linux command-line fundamentals
- Basic understanding of cybersecurity principles

## 🔧 Installation

### Step 1: Install Linux
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Snort
```bash
# Install dependencies
sudo apt install -y build-essential libpcap-dev libpcre3-dev \
libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev

# Install Snort
sudo apt install snort -y

# Verify installation
snort -V
```

### Step 3: Configure Network Interface
```bash
# Identify your network interface
ip addr show

# Configure Snort to monitor your network
sudo nano /etc/snort/snort.conf
```

Detailed installation instructions are available in the [Installation Guide](docs/installation-guide.md).

## 📅 Project Timeline

### Month 1: Foundation (Weeks 1-4)
**Focus**: Basic setup, traffic monitoring, and understanding Snort alerts

| Week | Key Tasks |
|------|-----------|
| 1 | Install Linux & Snort, basic CLI navigation |
| 2 | Configure network interface, run detection mode |
| 3 | Simulate basic attacks, observe alerts |
| 4 | Explore default rules, prepare initial report |

**Deliverable**: Report on installation, configuration, and basic alert analysis

### Month 2: Intermediate (Weeks 5-8)
**Focus**: Custom rule creation and attack simulation

| Week | Key Tasks |
|------|-----------|
| 5 | Learn rule syntax, write 2+ custom rules |
| 6 | Simulate TCP scans & SSH brute force |
| 7 | Identify false positives, tune alerts |
| 8 | Compile comprehensive report |

**Deliverable**: Detailed report with custom rules and optimization techniques

### Month 3: Advanced (Weeks 9-12)
**Focus**: Advanced logging, visualization, and final implementation

| Week | Key Tasks |
|------|-----------|
| 9 | Configure multi-output logging, set up notifications |
| 10 | Optimize performance, monitor resources |
| 11 | Implement alert visualization (ELK stack) |
| 12 | Final report, presentation, and submission |

**Deliverable**: Complete project documentation with visualizations and demo

## 📁 Project Structure

```
snort-nids-project/
├── README.md
├── docs/
│   ├── installation-guide.md
│   ├── configuration-guide.md
│   ├── rule-writing-tutorial.md
│   └── attack-simulation-guide.md
├── configs/
│   ├── snort.conf
│   └── local.rules
├── rules/
│   ├── custom-rules/
│   │   ├── icmp-detection.rules
│   │   ├── port-scan.rules
│   │   └── ssh-bruteforce.rules
│   └── README.md
├── scripts/
│   ├── attack-simulation/
│   │   ├── ping-flood.sh
│   │   ├── port-scan.py
│   │   └── ssh-brute.py
│   ├── log-analysis/
│   │   └── parse-alerts.py
│   └── README.md
├── reports/
│   ├── month-1-report.md
│   ├── month-2-report.md
│   ├── month-3-report.md
│   └── final-report.md
├── screenshots/
│   ├── installation/
│   ├── alerts/
│   └── dashboards/
└── LICENSE
```

## 🎮 Usage

### Basic Snort Commands

```bash
# Check Snort configuration
sudo snort -T -c /etc/snort/snort.conf

# Run Snort in IDS mode
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

# Run with custom rules
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0 \
-l /var/log/snort

# Test Snort against PCAP file
sudo snort -r traffic.pcap -c /etc/snort/snort.conf
```

### Writing Custom Rules

Example rule to detect ICMP ping:
```
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; \
sid:1000001; rev:1;)
```

See [Rule Writing Tutorial](docs/rule-writing-tutorial.md) for detailed guidance.

## 🎓 Learning Outcomes

By completing this project, learners will be able to:

- ✅ Install and configure Snort on Linux systems
- ✅ Monitor network traffic in real-time
- ✅ Understand and interpret Snort alert formats
- ✅ Write custom detection rules for specific threats
- ✅ Simulate various network attacks for testing
- ✅ Identify and suppress false positive alerts
- ✅ Optimize Snort performance for production use
- ✅ Implement multi-output logging and notifications
- ✅ Create visual dashboards for alert analysis
- ✅ Document and present cybersecurity projects professionally

## 📊 Deliverables

### Month 1
- Installation and setup report
- Traffic monitoring documentation
- Simulated attack analysis
- Understanding of Snort rules (with screenshots)

### Month 2
- Custom Snort rules documentation
- Attack simulation results
- False positive analysis
- Optimization strategies
- Optional presentation slides

### Month 3
- Complete project report (all months)
- Alert visualization dashboards
- Performance optimization documentation
- Final demo/presentation
- Complete technical documentation

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-rule`)
3. Commit your changes (`git commit -m 'Add amazing detection rule'`)
4. Push to the branch (`git push origin feature/amazing-rule`)
5. Open a Pull Request

Please ensure your contributions include:
- Clear documentation
- Comments in custom rules
- Testing evidence (screenshots/logs)

## 📚 Resources

### Official Documentation
- [Snort Official Website](https://www.snort.org/)
- [Snort User Manual](https://www.snort.org/documents)
- [Snort Rule Documentation](https://www.snort.org/rules)

### Tutorials & Guides
- [Snort IDS Installation Guide](https://www.snort.org/documents/snort-setup-guides)
- [Writing Snort Rules](https://www.snort.org/faq/readme-rules)
- [ELK Stack Setup](https://www.elastic.co/guide/index.html)

### Attack Simulation Tools
- [Nmap](https://nmap.org/) - Network scanning
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Password brute-forcing
- [hping3](http://www.hping.org/) - Network testing

### Communities
- [Snort Community](https://www.snort.org/community)
- [r/netsec](https://www.reddit.com/r/netsec/)
- [Security Stack Exchange](https://security.stackexchange.com/)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Hitendra Parmar** - [parmarhitendra](https://github.com/parmarhitendra/)
- **Rudra Patel** - [Rudyy1824](https://github.com/rudyy1824/)
## 🙏 Acknowledgments

- Snort development team for creating this powerful IDS
- Cybersecurity community for continuous knowledge sharing
- All contributors to this educational project

---

**⚠️ Disclaimer**: This project is for educational purposes only. Always ensure you have proper authorization before conducting security testing on any network. Unauthorized network scanning or attack simulation may be illegal in your jurisdiction.

**📧 Contact**: For questions or collaboration, please open an issue or contact [hitendraarjunsinhparmar@gmail.com] & [rudrapatel1824@gmail.com]

**⭐ If you found this project helpful, please consider giving it a star!**
