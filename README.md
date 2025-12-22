# SQL Automated Injection Tester

This repository contains `injection_script_degtest_V3.py`, a time-based blind SQL injection testing script targeting ASP.NET (MSSQL) endpoints. The script sends payloads that attempt to induce a server-side delay (via `WAITFOR DELAY`) and compares response times to a baseline to identify potential vulnerabilities.

File: [SQlAutomatedInjection/injection_script_degtest_V3.py](SQlAutomatedInjection/injection_script_degtest_V3.py)

## Purpose
- Perform automated time-based blind SQL injection tests against API endpoints defined in `endpoints.json`.
- Useful for security testing, pentesting, and vulnerability research (use responsibly).

## Requirements
- Python 3.8+
- `requests` library

Install dependencies (example):

```powershell
# activate virtualenv (Windows example)
.\myenv\Scripts\activate
pip install requests
```

## Usage
Run the script from the `SQlAutomatedInjection` folder. Basic invocation:

```powershell
python injection_script_degtest_V3.py [options]
```

Important CLI options:
- `--start` : Start index (default: 0)
- `--end` : End index (exclusive)
- `--limit` : Maximum number of endpoints to test
- `--controller` : Filter endpoints by controller name
- `--use-encoded` : Use URL-encoded payloads
- `--input` : Input JSON file with endpoints (default: `endpoints.json`)

Example:

```powershell
python injection_script_degtest_V3.py --start 0 --limit 50 --use-encoded
```

## How it works (brief)
- Loads endpoints from `endpoints.json`.
- Establishes a baseline response time by making a couple of requests with default parameter values.
- For each string parameter it injects time-delay payloads (e.g., `';WAITFOR DELAY '0:0:10'--`) and measures response time.
- If the response time increases beyond a configurable threshold (`DELAY_THRESHOLD` in the script), it marks the endpoint as potentially vulnerable.

## Output
- Results are saved to a JSON file named like `sqli_results_<start>_<end>_<timestamp>.json` in the working directory. The file contains baseline times, detected vulnerabilities, payloads used, and relevant metadata.

## Configuration & Safety Notes
- The script contains `HEADERS` and `COOKIES` dictionaries used for requests. Review and sanitize these before running (they may contain sensitive or environment-specific values).
- The script uses time-based payloads which deliberately slow the target. Use only against systems you own or have explicit authorization to test.
- Be mindful of rate limits and legal/ethical considerations. Follow responsible disclosure practices.

## Recommended next steps
- Review and, if needed, update `HEADERS` / `COOKIES` in the script.
- Consider adding a `requirements.txt` with `requests` for reproducible installs.
- If you want, I can add a small wrapper to run tests in parallel or integrate logging.

---
*This README was generated to document `injection_script_degtest_V3.py`. If you want changes (more examples, minimal `requirements.txt`, or CI/test integration), tell me which you'd like next.*
