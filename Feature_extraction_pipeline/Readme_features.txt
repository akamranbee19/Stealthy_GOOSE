The file `data/xlsx/naive-preprocessed.xlsx` is the final preprocessed file containing the features proposed by Lahza et al.:

https://www.sciencedirect.com/science/article/pii/S1874548216301688

The features are summarized in Table 4 of that paper.

The pipeline from `data/pcap/naive.pcapng` to `data/xlsx/naive-preprocessed.xlsx` looks like this:

Step 1 - Create a virtual environment and install dependencies by double-clicking `setup_venv.bat` inside `.\scripts`.

Step 2 - Activate the virtual environment. Open a PowerShell prompt in the repository root and run:
.\scripts\venv\Scripts\activate

Step 3 - Convert the PCAP file to Excel format. 
Note: The data is labeled using the VLAN PCP field, where label = 1 indicates attack traffic and label = 0 indicates benign traffic.
python scripts/pcap_parser.py data/pcap/naive.pcapng data/xlsx/naive-raw.xlsx

Step 4 - Extract the features proposed by Lahza et al.:
python scripts/extract_features.py --in data/xlsx/naive-raw.xlsx --out data/xlsx/naive-preprocessed.xlsx

foreach ($d in "F0","F1","F2","F3","F4") {
    python scripts/pcap_parser.py "data/pcap/$d.pcapng" "data/xlsx/$d-raw.xlsx"
}

foreach ($d in "V0","V1","V2","V3","V4") {
    python scripts/extract_features.py "data/xlsx/$d-raw.xlsx" "data/xlsx/$d-preprocessed.xlsx"
}


python SVM.py --train K-F0-preprocessed.xlsx `
>>                --test_files K-F1-preprocessed.xlsx K-F2-preprocessed.xlsx K-F3-preprocessed.xlsx K-F4-preprocessed.xlsx `
>>                --nu 0.001 --gamma 0.01


 .\.venv\Scripts\Activate.ps1    