Feature Extraction Pipeline
===========================

This folder contains the scripts used to convert IEC 61850 GOOSE packet captures into a preprocessed feature set for the SVM classifier.

The final preprocessed file is:

- `data/xlsx/naive-preprocessed.xlsx`

It contains the features proposed by Lahza et al. in:

https://www.sciencedirect.com/science/article/pii/S1874548216301688

The extracted features correspond to Table 4 in that paper.

Pipeline Overview
-----------------

1. `pcap_parser.py`: reads a GOOSE PCAP (`.pcapng`) and writes a raw Excel file containing parsed GOOSE fields, timing, length, and VLAN PCP labels.
2. `extract_features.py`: reads the raw Excel file and computes the 11 Lahza et al. sliding-window features for each GOOSE stream.
3. `SVM-FINAL.py`: consumes the preprocessed Excel file to train and evaluate the One-Class SVM detector.

Expected data flow:

- Input PCAP: `data/pcap-files/naive.pcapng`
- Raw Excel: `data/xlsx/naive-raw.xlsx`
- Preprocessed Excel: `data/xlsx/naive-preprocessed.xlsx`

Labeling
--------

The raw conversion uses the VLAN PCP field to label packets. In this dataset:

- `label = 1` indicates attack traffic
- `label = 0` indicates benign traffic

If a packet has `vlan_pcp == 0`, it is treated as malicious; otherwise it is treated as benign.

Requirements
------------

This pipeline is designed to run with Python 3.10.11.

Install Python 3.10.11 and then create the virtual environment from the repository root:

```powershell
py -3.10 -m venv .\venv
.\venv\Scripts\activate
```

If you need to force the exact 3.10.11 interpreter, use the full path to that Python executable:

```powershell
C:\Path\To\Python310\python.exe -m venv .\venv
.\venv\Scripts\activate
```

Step 2 - Install dependencies:

```powershell
pip install -r requirements.txt
```

Step 3 - Convert all PCAP files to raw Excel format from the repository root:

```powershell
mkdir .\data\xlsx
Get-ChildItem .\data\pcap-files\*.pcapng | ForEach-Object {
    $out = "data/xlsx/$($_.BaseName)-raw.xlsx"
    python Feature_extraction_pipeline\pcap_parser.py $_.FullName $out
}
```

Step 4 - Extract Lahza et al. features for all raw Excel files:

```powershell
Get-ChildItem .\data\xlsx\*-raw.xlsx | ForEach-Object {
    $base = $_.BaseName -replace '-raw$',''
    $out = "data/xlsx/$base-preprocessed.xlsx"
    python Feature_extraction_pipeline\extract_features.py --in $_.FullName --out $out
}
```

Running the SVM evaluation
--------------------------

`SVM-FINAL.py` loads preprocessed datasets from its hard-coded `DATA_DIR` path. Before running it, update the `DATA_DIR` constant in `SVM-FINAL.py` so it points to the directory containing:

- `benign-preprocessed.xlsx`
- `benign-test-preprocessed.xlsx`
- `naive-preprocessed.xlsx`
- `stealthy-preprocessed.xlsx`
- `ssaware-preprocessed.xlsx`

Then run:

```powershell
python ..\SVM-FINAL.py
```

(if you execute from the `Feature_extraction_pipeline` folder) or:

```powershell
python SVM-FINAL.py
```

from the repository root.

Notes
-----

- `extract_features.py` expects the raw Excel file to contain `EpochArrivalTime`, `Length`, `stNum`, `sqNum`, and `datSet`.
- `pcap_parser.py` uses PyShark to parse GOOSE packets and extract the raw frame bytes required for VLAN PCP labeling.
- The feature extraction pipeline is intended to create the dataset used by the main SVM evaluation script.
