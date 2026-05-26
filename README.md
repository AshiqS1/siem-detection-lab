# SIEM Detection Lab - for Threat Hunting & MITRE ATT&CK Simulation

## Introduction

This project showcases an end-to-end threat detection lab built using Splunk SIEM. It includes the detailed configurations and logging setup for 6 network devices, including walkthroughs for configuring the Splunk Universal Forwarder.

After the network infrastructure is configured and baseline VM snapshots are created, 5+ MITRE ATT&CK techniques are simulated across both Windows and Linux endpoints. The corresponding SPL detection logic is documented and implemented as custom Splunk alert rules to identify, monitor, and alert on simulated attacker activity.

## Executive Summary

This project documents an end-to-end threat detection lab built using free, commercially available tooling. The environment is hosted on-prem on a single Windows 11 Home machine using VMware Workstation Pro as the Type-2 hypervisor. 

The lab consists of 6 virtual machines (VMs) segmented into an internal LAN (`ASH-INT-LAN`) which is protected by a pfSense firewall and monitored by a centralized Splunk Enterprise SIEM server. 

The six network devices consist of: 
1. pfSense CE Network Firewall
2. Splunk SIEM Server (Linux Debian)
3. User Workstation (Linux Ubuntu)
4. User Workstation (Windows 11)
5. SQLDB Server (Linux Debian, headless)
6. Attackbox (Kali Linux)


