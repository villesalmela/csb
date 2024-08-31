# Cyber Security Base - Project 1
## Summary
This repository contains a simple web application with Flask and Sqlite3 database in the backend.
There are two tags: [flawed](https://github.com/villesalmela/csb/tree/flawed) and [fixed](https://github.com/villesalmela/csb/tree/fixed).
The first contains a version, that has 5 specific security flaws, and the latter contains a version where the flaws have been fixed.

All the flaws are from [OWASP Top 10 - 2021](https://owasp.org/Top10/)

## The Web Application
### Users
The app has two built-in users: `admin` and `user` with hardcoded credentials. The password is the same as the username.

### Functionality
- Both users can **log in**
- Both users can visit the profile page, to **set their nickname**
- Only the admin user can visit the admin panel, to **view a list of all profiles**
- Both users can **log out**

### Installation
0. Install Python 3.12: https://www.python.org/downloads/
1. Install poetry, a Python dependency manager: https://python-poetry.org/docs/#installation
2. Download this repository to your workstation
3. Open the repository root folder in a terminal
4. Run `poetry install` to install needed dependencies

### Usage
0. Run `poetry run python main.py` to launch the application
1. A message informs you where the application is served. For example: `* Running on http://127.0.0.1:5000`
2. Use a web browser, go to the given address

## The security flaws
### Security Flaw 1: [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
Related weakness: [CWE-352 - Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)  
Location: [314522e](https://github.com/villesalmela/csb/commit/314522e74a73e5f8eb3bfb1c22753ed76f4f3eff)

#### Problem
The CSRF token is not validated before saving the submitted data.

When a user first requests the `/profile` page (GET), a random CSRF token is generated. This token is saved to the server-side database, and linked to both the username and their session ID.
The token is returned in the response, included in a hidden field within the form.

When the user then submits the form from `/profile` page (POST), the flawed app fails to check if the provided CSRF token is valid. In this configuration, it is possible that the user is browsing a malicious third-party website, and a script is making the request on behalf of the user, without the user's permission.

#### Solution
Read the username, session ID, and CSRF token from the POST request, and check if that combination can be found in the server-side database. If a match is found, then the request is valid, otherwise it needs to be rejected. A malicious website would fail to retrieve a valid CSRF token, due to how browsers implement Same-Origin Policy (SOP). By default, the SOP prevents any script on the malicious website from accessing the response content, if the response originates from a different domain.

### Security Flaw 2: [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
Related weakness: [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)  
Location: [f2d43c4](https://github.com/villesalmela/csb/commit/f2d43c4f2fe3b0a19e81cf166ab3008c6452c2b9)

#### Problem
An insecure hashing algorithm, MD5, is used when hashing user passwords. Due to advancements in cryptography and an increase in computing power, MD5 is no longer considered secure for cryptographic purposes. If an attacker gets unauthorized access to the server-side database, they could relatively easily recover plaintext passwords for all users.

#### Solution
Use a cryptographically secure hashing algorithm, such as SHA256.

### Security Flaw 3: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
Related weakness: [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
Location: [a5e77fc](https://github.com/villesalmela/csb/commit/a5e77fcae43fab893d2d46f4c17c2dcafeb5eefc)

#### Problem
User-provided untrusted data is not escaped before rendering.

A malicious user could browse to `/profile` page and set their nickname as `<script>alert(Running malicious code now)</script>`. When an admin goes to `/admin` page to view a list of all profiles, the malicious script would run on their browser without any interaction.

#### Solution
If untrusted data is rendered on a page, it is first escaped, turning all the content into text that will not execute.
Normally web application frameworks handle this automatically if using page templates, but it can also be done more manually, like in this solution.

### Security Flaw 4: [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
Related weakness: [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)  
Location: [aa4f147](https://github.com/villesalmela/csb/commit/aa4f1471b331cc822edada2904dc7c493e744bb1)

#### Problem
User-provided identity claim is not validated before use.

An attacker could manually insert a cookie `logged_in_as` to value `admin`, to gain administrator rights. In this configuration, the flawed application fails to prove that the identity claim is correct.

#### Solution
During the login process, the user is authenticated by verifying that they have access to the correct password. Only if this authentication is successful, a random session ID is generated and associated with the username, and both are saved to the server-side database. The user will receive this session ID to keep in their cookies. Now whenever a user claims to have some identity, they must also provide a session ID. The fixed application will check if the session ID & username combination can be found in the serverside database. If a match is found, it indicates that the user has already proved their identity during login.

### Security Flaw 5: [A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
Related weakness: [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)  
Location: [d1cf50a](https://github.com/villesalmela/csb/commit/d1cf50a5eeb8eecfc5e0f7c3e081c9ab9c302733)

#### Problem
Plaintext passwords are written to a log file when any user logs in at `/login` page.

If an attacker would gain access to the log file, they would also have access to plaintext passwords of all users, that had recently logged in.

#### Solution
Identify the sensitive information and remove it from the log message, before writing it to the file.