# Cobalt Sentry

Cobalt Sentry is a memory scanning tool designed to detect Cobalt Strike beacons and other stealthy malware techniques, such as Hell's Gate and Heaven's Gate, in running processes on Windows systems.

## Features
- Scans all running processes or a specific PID.
- Detects Cobalt Strike beacons using various techniques, including:
  - SleepMask detection (high entropy memory regions).
  - Mask detection (XORed).
  - BeaconGate (API redirection techniques).
  - UDRL (Userland Reflective Loader) detection.
  - XOR-encoded beacon configuration scanning.
  - Hell's Gate and Heaven's Gate syscall manipulation detection.
- Supports multi-threaded scanning for efficiency.

## Requirements
- Windows operating system.
- Go installed (1.18 or later).
- Administrator privileges for accessing process memory.

## Installation
Clone the repository and build the tool:
```sh
git clone https://github.com/MazX0p/CobaltSentry.git
cd CobaltSentry
go mod tidy
```

Build the executable:
```sh
go build -o CobaltSentry.exe
```

## Usage
Run the tool with the following options:

Scan all running processes:
```sh
CobaltSentry.exe -all
```

Scan a specific process by PID:
```sh
CobaltSentry.exe -pid <PID>
```

## Example Output

![image](https://github.com/user-attachments/assets/658a4520-1198-45d9-a76a-68af6ebdc892)


```
############################################
#            (\\(\\                          #
#            ( -.-)                        #
#           o((\")(")                       #
#                                          #
#         C O B A L T  S E N T R Y         #
#  Cobalt Strike & Hell's Gate Scanner     #
#     Created by Mohamed Alzhrani (0xmaz)  #
############################################

Scanning in progress...
[!] Suspicious activity detected in PID 1234 at address 0x7ffabcd1234 It Maybe:
    - SleepMask Detected: High entropy in memory
    - UDRL Detected: Modified or missing PE header
    - BeaconGate Detected: API call proxying found
```

## Disclaimer
This tool is intended for security research and educational purposes only. The author is not responsible for any misuse or damage caused by this tool.

## Author
- **Mohamed Alzhrani (0xmaz)**

## Contributions
Contributions and improvements are welcome. Feel free to submit pull requests or open issues.

## Contact
For inquiries or suggestions, please reach out via GitHub issues.

