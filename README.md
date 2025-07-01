# ivs-SuspiciousProcessMonitor
A command-line tool that monitors running processes on a host and flags processes with unusual characteristics, such as unsigned binaries, unusual network connections, or high CPU usage. Uses `psutil` library. - Focused on Simple vulnerability scanner focusing on common misconfigurations in web infrastructure. Checks for exposed `.env` files, common admin panels, and outdated software versions by crawling a target website and analyzing responses.

## Install
`git clone https://github.com/ShadowGuardAI/ivs-suspiciousprocessmonitor`

## Usage
`./ivs-suspiciousprocessmonitor [params]`

## Parameters
- `-h`: Show help message and exit
- `--crawl_depth`: No description provided
- `--output_file`: No description provided
- `--verbose`: Enable verbose output.

## License
Copyright (c) ShadowGuardAI
