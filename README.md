# Prep4Faraday

Pref4Faraday works as a tool to prepare inputs for Faraday. It takes several csv files (outputs from Nessus, Nmap and Acunetix) and returns one output file (`.xml`).

Supported services are (for now):
- Nessus
- Acunetix
- Nmap

## Requirements

- Python 3.x
- pip

## Usage

First head to `Config/InputConfig.json` and add al the files you wish to unify, something like the following.  

```
[
    {
        "Filename": "acu_example.csv",
        "Service": "Acunetix"
    },
    {
    	"Filename": "nessus_example.csv",
        "Service": "Nessus"
    },
    {
    	"Filename": "nmap_example.csv",
        "Service": "Nmap"
    }
]
```

Remember to put the files inside the `Input` folder (Names must match!)  

Then simply run the program with  

Windows  
`py prep4Faraday.py <OUTPUT_FILENAME>`  

Linux  
`python3 prep4Faraday.py <OUTPUT_FILENAME>`  

## Setup

`pip install -r requirements.txt`  
