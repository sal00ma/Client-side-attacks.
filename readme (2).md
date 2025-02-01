Agenda:

XSS

CSRF

CORS

Cross-site scripting (XSS)
It allows attackers to inject malicious scripts into web pages viewed by other users. These scripts are usually written in JavaScript, but other types of code like HTML, Flash, or even JavaScript-based code can also be used.

There are three main types of XSS attacks:

Stored XSS: The malicious script is permanently stored on the server (in a database) and is served to all users who view the affected page.
A user submits a comment on a blog post:

<script>alert("XSS attack");</script>

Any user who visits the blog post will now receive the alert message within the application’s response.


Reflected XSS: The malicious script is reflected off the web server, typically through a URL or input field, and is executed immediately in the user’s browser.
A user submits the malicious script in the URL

http://example.com/search?query=<script>alert('Hacked!');</script>

When the victim clicks the link, the script gets executed in their browser and an alert box appears.

DOM-based XSS(Client-side XSS): The vulnerability exists in the client-side code, where the malicious script manipulates the Document Object Model (DOM) of the page.
Scenario: Imagine a website that allows users to search for products. When a user submits a search, the search term is reflected in the page as part of the results. The page uses JavaScript to dynamically display the search term.

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Search Results</title>
</head>
<body>
  <h1>Search Results</h1>
  <div id="results">
    <!-- Search term will be inserted here dynamically -->
  </div>

  <script>
    // Get the search query from the URL
    var searchQuery = new URLSearchParams(window.location.search).get('query');

    // Insert the search term into the page (vulnerable code)
    document.getElementById('results').innerHTML = "Results for: " + searchQuery;
  </script>
</body>
</html>
In the above code, the search term (query) from the URL is extracted using JavaScript (window.location.search) and directly inserted into the HTML using innerHTML. This is dangerous because it does not sanitize the input, allowing an attacker to inject malicious scripts into the page.

The Attack

http://example.com/search?query=<script>alert('XSS');</script>

NOTE : Alert function just an example to proof the XSS exploit but you can apply any malicious script.

Differences between Reflected XSS and DOM-based XSS:

Reflected XSS:
Where it happens: Server reflects malicious input back to the browser.
Who is responsible: Server handles the malicious input.
Example: Malicious input in URL is reflected back by the server (e.g., ?query=<script>).
DOM-based XSS:
Where it happens: Browser executes malicious input through client-side JavaScript.
Who is responsible: Client-side JavaScript handles the malicious input.
Example: Malicious input in URL is processed by JavaScript and injected into the DOM (e.g., ?msg=<script>).
In summary:
Reflected XSS is server-driven.
DOM-based XSS is client-side JavaScript-driven.

Impact of XSS vulnerabilities
Cookies and Session Data: Attackers can steal cookies, session tokens, or authentication credentials, allowing them to hijack user sessions.
Sensitive Information: If sensitive data is displayed on the page or in a user’s input, attackers can retrieve it.
Malware Distribution: Attackers can use XSS to inject malicious scripts that download and execute malware on the user’s system, leading to further compromises like ransomware, keyloggers, or data breaches.
Phishing Attacks: XSS can be used to display fake login forms or redirect users to malicious sites that look legitimate, tricking them into entering sensitive data such as username, password, or credit card details.
Defacement: An attacker can use XSS to alter the appearance of a webpage (e.g., by changing text, images, or layout), damaging the reputation of the website or confusing users.
How to find and test for XSS vulnerabilities?
Identify all input points (form fields, URL parameters, cookies, etc.).
Test with Basic Payloads
Insert common XSS payloads such as:

<script>alert('XSS')</script>

<img src="x" onerror="alert('XSS')">

<svg onload="alert('XSS')">

Check if these payloads are reflected back or executed by the application.

Test URL Parameters
Test query parameters in URLs (e.g., ?query=<script>alert('XSS')</script>) to see if input is reflected back in the response.

Use automated tools like Burp Suite, ZAP, or XSStrike to scan for vulnerabilities.
Check for reflected, stored, and DOM-based XSS.
Ensure that input data is properly sanitized and encoded on both the server and client sides:
Sanitize input: Remove or encode dangerous characters like <, >, &, and ".

Encode output: Ensure that user input is encoded before being inserted into HTML, JavaScript, or other contexts.

How to prevent XSS?
Sanitize input and encode output:
Remove dangerous characters: Eliminate characters like <, >, &, ", ', ;, and others that can be used for script injection.

Use libraries: Use well-established libraries for input sanitization (e.g., DOMPurify for sanitizing HTML input).

HTML Encoding: Use functions that convert special characters (<, >, ", etc.) into their HTML entity equivalents (e.g., &lt;, &gt;, &quot;).

JavaScript Encoding: If you’re embedding user input in JavaScript, ensure it’s properly escaped or encoded.

URL Encoding: Ensure that input used in URLs or query parameters is properly encoded to prevent script injection.

Avoid using dangerous methods like innerHTML, document.write(), and eval().
Implement a Content Security Policy (CSP).
Use HTTP-only and Secure cookies.
Validate and sanitize server-side.
Leverage secure frameworks that automatically escape data.
Avoid inline JavaScript and use external scripts.
Regularly update and patch libraries.
Test for XSS vulnerabilities regularly.

“Let’s move on to the next one”
CSRF (Cross-Site Request Forgery)
in a very simple mean an attacker tricks a user into performing his malicious script on a website where the user is authenticated.


Scenario:

A typical flow of a CSRF attack

The attacker creates a malicious website or sends a link to a user (victim).
The user clicks on the link or visits the malicious website while logged in to the vulnerable website.
The malicious website sends a request to the vulnerable website with the user’s cookies and the attacker’s desired action, such as form submission or money transfer.
The vulnerable website, not knowing that the request is from an attacker (malicious website) and not from the user, processes the request and performs the attacker’s desired action.

Methodology
What is the impact of a CSRF attack?
Unauthorized Transactions: Financial or resource-based actions without the user’s consent (e.g., transferring money, purchasing goods).
Data Modification: Changing or deleting user data, account settings, or content.
Privilege Escalation: Gaining higher access privileges (e.g., admin rights).
Reputation Damage: Creating or modifying harmful content, which could damage an organization’s reputation.
Security Breach: Gaining access to sensitive data or systems, especially when combined with other vulnerabilities.
CSRF bypasses
I will mention a couple of CSRF bypass techniques:

Remove only the value of a token. (Keep the parameter)
CSRF tokens are generated by server-side applications and sent to clients as unique, secret, and unpredictable values.

Bypassing the CSRF by removing the token parameter.
Use the attacker’s own CSRF Token. (this will bypass CSRF defense if the csrf token is not tied with the user’s session)
Bypassing the CSRF by changing the request method.
Bypassing CSRF using XSS.
Bypassing same-site Attributes.
The SameSite cookie feature of the browser allows it to detect when cookies from one website are included in a request from another.
Replace the token with the same length random string.
If CSRF mitigates using a referrer header, there are a couple of things you can try, Remove the Referer Header:

<meta name="referrer" content="no-referrer">
CORS (Cross-Origin Resource Sharing)
Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP).


The CORS mechanism supports secure cross-origin requests and data transfers between browsers and servers. Browsers use CORS in APIs such as fetch() or XMLHttpRequest to mitigate the risks of cross-origin HTTP requests.

Same-Origin Policy (SOP):
Before CORS, the Same-Origin Policy was implemented to prevent a web page from making requests to a different domain (cross-origin).

Same-origin means the protocol, domain, and port must be the same for both the client and server.

Why CORS Exists?
CORS was introduced to allow controlled access to resources on a different domain, while still preventing potential security risks.
CORS allows a server to specify which domains are allowed to access its resources, offering flexibility and security.
The CORS policy is defined by setting HTTP headers on the server. These headers include:

Access-Control-Allow-Origin: Specifies which domains are allowed to access the resource.
Access-Control-Allow-Credentials: Specifies which HTTP methods (GET, POST, etc.) are allowed.
Common CORS Vulnerabilities and Risks
Wildcard * in Access-Control-Allow-Origin

Description: A server that uses a wildcard (*) in the Access-Control-Allow-Origin header allows any origin to access its resources.
Risk: Malicious websites could make requests to your API and steal sensitive information (e.g., user data, authentication tokens).
Access-Control-Allow-Origin: *
Mitigation: Allow only the trusted origins. For instance:

Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials header is set to true

. Risk: If the server responds with both Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true, any website can access your API with credentials (cookies or session data), potentially exposing user sessions and sensitive information.

Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Mitigation: Always ensure that Access-Control-Allow-Origin is not a wildcard when you allow credentials. It should only be a specific origin:

Access-Control-Allow-Origin: https://secureorigin.com
Access-Control-Allow-Credentials: true
CORS and CSRF (Cross-Site Request Forgery)

Description: If CORS is not correctly configured, it can make an application more susceptible to CSRF attacks.
Risk: If CORS is not set up to ensure proper authorization, attackers can perform CSRF attacks using cross-origin requests.
Mitigation: Implement CSRF tokens and ensure that the CORS configuration requires authentication for sensitive actions.
Resources:
.PortSwigger

.HTB

.Cobalt


See U next write-up.
I hope it will be helpful for your first steps.
