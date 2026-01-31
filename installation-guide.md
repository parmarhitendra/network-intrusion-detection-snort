# Snort Installation Guide

This guide provides detailed step-by-step instructions for installing and configuring Snort on Linux systems.

## Table of Contents
- [System Requirements](#system-requirements)
- [Installing on Ubuntu](#installing-on-ubuntu)
- [Installing on Kali Linux](#installing-on-kali-linux)
- [Post-Installation Configuration](#post-installation-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04+ or Kali Linux 2021.1+
- **RAM**: 4GB (8GB recommended)
- **Disk Space**: 20GB free
- **Network**: Active network interface card
- **Processor**: 2 CPU cores (4 cores recommended)

### Software Dependencies
- libpcap
- libpcre3
- libdumbnet
- DAQ (Data Acquisition library)
- zlib
- OpenSSL

## Installing on Ubuntu

### Step 1: Update System

```bash
# Update package lists
sudo apt update

# Upgrade existing packages
sudo apt upgrade -y
```

### Step 2: Install Dependencies

```bash
# Install required dependencies
sudo apt install -y build-essential libpcap-dev libpcre3-dev \
libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl \
libssl-dev libnghttp2-dev
```

### Step 3: Install DAQ Library

```bash
# Download DAQ
cd /tmp
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz

# Extract and install
tar -xvzf daq-2.0.7.tar.gz
cd daq-2.0.7
./configure
make
sudo make install
```

### Step 4: Install Snort

**Option A: Install from Package Manager (Easier)**
```bash
sudo apt install snort -y
```

**Option B: Install from Source (Latest Version)**
```bash
# Download Snort
cd /tmp
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz

# Extract
tar -xvzf snort-2.9.20.tar.gz
cd snort-2.9.20

# Configure, compile, and install
./configure --enable-sourcefire
make
sudo make install

# Update shared libraries
sudo ldconfig

# Create symbolic link
sudo ln -s /usr/local/bin/snort /usr/sbin/snort
```

### Step 5: Create Snort User and Directories

```bash
# Create snort user
sudo groupadd snort
sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort

# Create directories
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /etc/snort/preproc_rules
sudo mkdir /var/log/snort
sudo mkdir /usr/local/lib/snort_dynamicrules

# Set permissions
sudo chmod -R 5775 /etc/snort
sudo chmod -R 5775 /var/log/snort
sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules
sudo chown -R snort:snort /etc/snort
sudo chown -R snort:snort /var/log/snort
sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules
```

### Step 6: Download and Setup Configuration Files

```bash
# Create required files
sudo touch /etc/snort/rules/white_list.rules
sudo touch /etc/snort/rules/black_list.rules
sudo touch /etc/snort/rules/local.rules

# Download community rules (optional but recommended)
cd /tmp
wget https://www.snort.org/downloads/community/community-rules.tar.gz
tar -xvzf community-rules.tar.gz
sudo cp community-rules/* /etc/snort/rules/
```

## Installing on Kali Linux

Kali Linux often has Snort pre-installed or available in repositories:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Snort
sudo apt install snort -y

# Verify installation
snort -V
```

## Post-Installation Configuration

### Configure Network Settings

1. **Identify your network interface:**
```bash
ip addr show
# or
ifconfig
```

2. **Edit Snort configuration:**
```bash
sudo nano /etc/snort/snort.conf
```

3. **Update these key variables:**
```conf
# Set your network
ipvar HOME_NET 192.168.1.0/24  # Change to your network

# Set external network
ipvar EXTERNAL_NET !$HOME_NET

# Set rule paths
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules

# Set your network interface (if needed)
# config interface: eth0
```

### Configure Logging

Edit `/etc/snort/snort.conf` and configure output:

```conf
# Unified2 logging
output unified2: filename snort.log, limit 128

# Alert to console (for testing)
output alert_fast: alert.ids
```

### Create Basic Local Rules

Edit `/etc/snort/rules/local.rules`:

```bash
sudo nano /etc/snort/rules/local.rules
```

Add a test rule:
```
# Alert on ICMP ping
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
```

## Verification

### Test Configuration

```bash
# Test configuration file
sudo snort -T -c /etc/snort/snort.conf

# Expected output should end with:
# Snort successfully validated the configuration!
```

### Test Detection

**Terminal 1 - Run Snort:**
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

**Terminal 2 - Generate Traffic:**
```bash
ping -c 5 192.168.1.1  # Replace with an IP in your network
```

You should see alerts in Terminal 1.

### Check Snort Version

```bash
snort -V

# Output should show:
#    ,,_     -*> Snort! <*-
#   o"  )~   Version 2.9.x.x GRE (Build XXX)
```

## Troubleshooting

### Common Issues

**Issue: "ERROR: Can't open pcap file"**
```bash
# Solution: Run with sudo
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

**Issue: "ERROR: /etc/snort/rules/white_list.rules(0) Unable to open"**
```bash
# Solution: Create missing files
sudo touch /etc/snort/rules/white_list.rules
sudo touch /etc/snort/rules/black_list.rules
```

**Issue: "WARNING: No preprocessors configured for policy 0"**
```bash
# Solution: Ensure preprocessors are uncommented in snort.conf
# Edit /etc/snort/snort.conf and verify preprocessor lines are active
```

**Issue: Network interface not found**
```bash
# Solution: Check available interfaces
ip link show

# Update snort.conf with correct interface
sudo nano /etc/snort/snort.conf
```

### Logs Location

Check logs if Snort crashes or doesn't start:
```bash
# System logs
sudo tail -f /var/log/syslog

# Snort logs
sudo tail -f /var/log/snort/alert

# Check if Snort is running
ps aux | grep snort
```

### Performance Issues

If Snort is slow or dropping packets:

```bash
# Disable unnecessary preprocessors
# Comment out unused rules
# Increase memory allocation
# Use faster storage for logs
```

## Next Steps

After successful installation:

1. ✅ Read the [Configuration Guide](configuration-guide.md)
2. ✅ Learn [Rule Writing](rule-writing-tutorial.md)
3. ✅ Try [Attack Simulations](attack-simulation-guide.md)
4. ✅ Explore [Alert Management](../README.md#month-3-advanced)

## Additional Resources

- [Official Snort Documentation](https://www.snort.org/documents)
- [Snort User Manual](https://www.snort.org/documents/snort-users-manual)
- [Snort FAQ](https://www.snort.org/faq)

---

**Note**: This guide is maintained as part of the Snort NIDS educational project. For the most current installation instructions, always consult the official Snort documentation.
