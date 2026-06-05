# IEC 61850 Cybersecurity Testbed — GOOSE Spoofing Detection

A hardware-in-the-loop testbed for evaluating intrusion detection against GOOSE spoofing attacks in IEC 61850-enabled substations. Built using real IEDs (ABB REF615 and Siemens SIPROTEC 5), this project implements three escalating GOOSE attack levels and a One-Class SVM baseline IDS, evaluated using standard detection metrics.

> Developed as part of a Master's thesis at **KTH Royal Institute of Technology**, in collaboration with **Omexom Sweden (Vinci Energies)**.

---

## Table of Contents

- [Overview](#overview)
- [Testbed Architecture](#testbed-architecture)
- [Attack Scenarios](#attack-scenarios)
- [Intrusion Detection System](#intrusion-detection-system)
- [License](#license)

---

## Overview

IEC 61850 substations rely on GOOSE (Generic Object-Oriented Substation Event) messages for time-critical protection and control. Because GOOSE operates over Ethernet with no built-in authentication in legacy deployments, it is vulnerable to spoofing attacks that can trigger false tripping or block legitimate commands.

This project provides:

- A **physical testbed** with real cross-vendor IEDs configured via SCL (System Configuration Language) files
- **Three GOOSE spoofing attack scripts** of escalating sophistication
- A **One-Class SVM IDS** trained on benign traffic features, evaluated across multiple detection thresholds
- Packet capture datasets and analysis tooling

---

## Testbed Architecture

The testbed consists of the following components:

| Component | Role |
|---|---|
| ABB REF615 | Protection IED (publisher / subscriber) |
| Siemens SIPROTEC 5 | Protection IED (publisher / subscriber) |
| Hirschmann managed switch | VLAN segmentation + SPAN port mirroring |
| Monitoring PC | Packet capture (Wireshark / Scapy) and IDS execution |

Cross-vendor GOOSE communication is configured by exchanging SCD (Substation Configuration Description) files between ABB PCM600 and Siemens DIGSI 5.

## Attack Scenarios

Three GOOSE spoofing attack levels are implemented as Python scripts using Scapy:

### Level 1 — Naive Attack
Injects GOOSE frames using a randomly chosen `stNum`, then increments `sqNum` with each subsequent packet. Because `stNum` is not derived from the observed legitimate stream, it will almost certainly mismatch the current state of the publisher, making this attack trivially detectable by any stateful monitor.

### Level 2 — Stealthy Attack
Increments `stNum` and `sqNum` using a randomly chosen `stNum`, then increments `sqNum` with each subsequent packet but distributes its footprint into different GOOSE streams. 

### Level 3 — SSAware Attack
Continuously monitors the live GOOSE stream and injects frames that match the current `stNum` and `sqNum` with a small delay. Injected packets overlap with benign switching events, making the attack well hidden.

---

## Intrusion Detection System

The IDS is a **One-Class SVM** trained exclusively on benign GOOSE traffic. Features are extracted per packet using a sliding window approach, based on the methodology of Lahza et al.

https://www.sciencedirect.com/science/article/pii/S1874548216301688

The features are summarized in Table 4 of that paper.

## License

This project is released under the [MIT License](LICENSE).

---

*KTH Royal Institute of Technology — Division of Electric Power and Energy Systems*
*Omexom Sweden (Vinci Energies)*
