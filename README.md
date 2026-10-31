![Banner](banner.png)

# ivs-website-misconfiguration-scanner
A command-line scanner that crawls a target website you name and checks it for common misconfigurations: exposed `.env` files, common admin panel paths, and software version hints in page markup. It uses `requests` and `bs4`. It does not monitor running processes, and it does not use `psutil`.

The `.env` check flags a probed path that answers 200 and whose body holds a common env marker (for example `APP_KEY`, `DB_HOST`, `DB_PASSWORD`, `SECRET_KEY`, or `DATABASE_URL`) or a `KEY=value` line shape. The admin panel check flags a path that answers 403, or a path that answers 200 with a login or admin marker in the body. A bare 200 is not flagged, because catch-all sites answer 200 for every path.

A scan that fetches no page at all is a failed scan: it prints no findings lines, does not claim the scan completed, and exits 1. A report file given with `--output_file` is written only after the scan completes, so a failed scan leaves a pre-existing output file unchanged.

## Install
`git clone https://github.com/ShadowGuardAI/ivs-website-misconfiguration-scanner`

## Usage
`python3 main.py [params] target_url`

## Parameters
- `target_url`: The target website URL to scan. Required.
- `-h`: Show help message and exit
- `--crawl_depth`: Maximum depth to crawl (default: 3).
- `--output_file`: File to save scan results (default: console output).
- `--verbose`: Enable verbose output.

## License
Copyright (c) ShadowGuardAI
