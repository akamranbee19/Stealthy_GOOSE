# Stealthy GOOSE — IEC 61850 GOOSE Dataset

A labelled network traffic dataset for evaluating intrusion detection against GOOSE spoofing attacks in IEC 61850-enabled substations. Captured on a physical hardware-in-the-loop testbed using real IEDs (ABB REF615 and two Siemens SIPROTEC 5 devices), the dataset covers benign GOOSE traffic and three escalating attack categories, alongside a One-Class SVM baseline IDS for reference evaluation.

> Released as part of a Master's thesis at **KTH Royal Institute of Technology**, in collaboration with **Omexom Sweden (Vinci Energies)**.

---

## Table of Contents

- [Overview](#overview)
- [Testbed Architecture](#testbed-architecture)
- [Dataset](#dataset)
- [Attack Scenarios](#attack-scenarios)
- [Baseline IDS](#baseline-ids)
- [Getting Started](#getting-started)
- [Citation](#citation)
- [License](#license)

---

## Overview

IEC 61850 substations rely on GOOSE (Generic Object-Oriented Substation Event) messages for time-critical protection and control. Because GOOSE operates over Ethernet with no built-in authentication in legacy deployments, it is vulnerable to spoofing attacks that can trigger false tripping or block legitimate commands.

This dataset provides:

- **Pcap files** of benign and attack GOOSE traffic captured from real IED hardware
- **Preprocessed Excel files** derived from the pcaps via feature extraction scripts included in the repository
- **Three labelled attack categories** of escalating sophistication (Naive, Stealthy, Substation Aware)
- A **One-Class SVM baseline IDS** with Optuna-based hyperparameter optimization for reference benchmarking

---

## Testbed Architecture

| Component | Role |
|---|---|
| ABB REF615 | Protection IED (publisher / subscriber) |
| Siemens SIPROTEC 5 (x2) | Protection IEDs (publisher / subscriber) |
| Hirschmann RSP25 managed switch | VLAN segmentation and SPAN port mirroring |
| Monitoring PC | Packet capture (Wireshark / Scapy) and IDS execution |

Cross-vendor GOOSE communication is configured by exchanging SCD (Substation Configuration Description) files between ABB PCM600 and Siemens DIGSI 5. The monitoring PC captures all GOOSE traffic via the SPAN port.

---

## Dataset

The `Data/` folder contains pcap files recorded on the physical testbed, covering benign GOOSE traffic and all three attack categories. All traffic originates from real IED hardware.

The preprocessed Excel files (one per capture) are derived from these pcaps using the feature extraction scripts included in the project. All three attack datasets share the same packet budget of 144 injected attack packets, enabling direct comparison across attack levels. The feature schema follows Table 4 in Lahza et al. (2018); see the [Citation](#citation) section below.

| Dataset | Total Packets | Normal | Attack | Duration (s) |
|---|---|---|---|---|
| Benign (training) | 3,736 | 3,736 | 0 | 1201 |
| Benign (testing) | 3,597 | 3,597 | 0 | 1151 |
| Naive | 3,898 | 3,754 | 144 | 1202 |
| Stealthy | 3,894 | 3,750 | 144 | 1200 |
| Substation Aware | 3,905 | 3,761 | 144 | 1204 |

---

## Attack Scenarios

Three GOOSE spoofing attack categories are captured, generated using Python scripts with Scapy:

### Level 1 — Naive Attack

Injects GOOSE frames with randomly chosen `stNum` and `sqNum` values. Within each injected burst, `stNum` remains fixed while `sqNum` is incremented, mimicking the normal GOOSE retransmission pattern. Because `stNum` is not derived from the observed legitimate stream, injected packets will almost certainly mismatch the current publisher state, making this attack trivially detectable by any stateful monitor.

### Level 2 — Stealthy Attack

Injects GOOSE frames with randomly chosen `stNum` and `sqNum` values. Within each injected burst, `stNum` remains fixed while `sqNum` is incremented, mimicking the normal GOOSE retransmission pattern. Injected frames are distributed across multiple GOOSE streams to reduce the per-stream anomaly footprint. The goal is to evade simple per-stream rate or counter monitors.

### Level 3 — Substation Aware Attack

Continuously monitors the live GOOSE stream and injects frames with `stNum` and `sqNum` values matched to the current legitimate sequence, introducing only a small delay. Injected packets overlap temporally and numerically with benign switching events, making them geometrically indistinguishable from normal state transitions in the feature space used by the IDS.

---

## Baseline IDS

A One-Class SVM baseline IDS is provided in `SVM-FINAL.py` as a reference for benchmarking against this dataset. The model is trained exclusively on benign GOOSE traffic, with the contamination parameter `nu` tuned via Optuna (50 trials, maximizing AUC-PR). Evaluation is run separately for each attack category against the held-out benign test set, reporting AUC-ROC, AUC-PR, TPR at fixed FPR targets, and a TPR vs FPR chart.

---

## Getting Started

Python 3.10 is recommended. Install dependencies with:

```bash
pip install -r requirements.txt
```

Then update the `DATA_DIR` path at the top of `SVM-FINAL.py` to point to the `Data/` folder and run:

```bash
python SVM-FINAL.py
```

---

## Citation

If you use this dataset in your research, please cite the thesis:

> A. Kamran, *Testing and Cybersecurity of IEC 61850 Enabled Substations*, Master's thesis, KTH Royal Institute of Technology, Division of Electric Power and Energy Systems, Stockholm, Sweden, 2025.

The sliding-window feature extraction methodology follows:

> H. Lahza, K. Radke, and E. Foo, "Applying domain-specific knowledge to construct features for detecting distributed denial-of-service attacks on the GOOSE and MMS protocols," *International Journal of Critical Infrastructure Protection*, 2018. [https://doi.org/10.1016/j.ijcip.2017.12.002](https://doi.org/10.1016/j.ijcip.2017.12.002)

---

## License

This project is released under the [MIT License](LICENSE).

---

*KTH Royal Institute of Technology — Division of Electric Power and Energy Systems*  
*Omexom Sweden (Vinci Energies)*
