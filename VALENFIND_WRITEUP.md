# Valenfind - First CTF Writeup

This is my first CTF writeup. In this challenge, I followed a standard enumeration-first approach and eventually found an **LFI vulnerability** that led to the flag.

## 1. Initial Enumeration

I started with:
- `nmap` to scan open ports
- `gobuster` to discover hidden directories/endpoints

Then I reviewed the application behavior and source code carefully, while also testing common vulnerabilities like:
- SQL injection
- Command injection

For CTFs, I also recommend capturing and inspecting requests (Burp/packet capture), because important clues often appear there.

## 2. Suspicious Functionality

After logging in, I noticed one account named **cupid** looked suspicious:
- It had around **1000 likes**
- Other accounts had far fewer likes

That made it a good target for deeper testing.

## 3. Request Enumeration

While analyzing traffic, I found a request path related to:
- `profile/cupid`
- `api/fetch/layout`

I tested path traversal payloads on that endpoint and used:

```bash
../../../../etc/passwd
```

This worked, confirming an **LFI (Local File Inclusion)** vulnerability.

## 4. Source Code Disclosure via LFI

Using the same LFI technique, I enumerated more files and found:

- `/opt/valenfind/app.py`

From `app.py`, I discovered:
- An API key
- Database-related information/location in source code

## 5. Privileged API Access and Flag

I modified requests by adding the header:

```http
x-valentine-token: <api_key>
```

With the correct token, I gained access to protected functionality and retrieved the flag.

## Lessons Learned

- Always do thorough enumeration first.
- Small anomalies (like the cupid profile) can be the key clue.
- LFI can lead to source code exposure, secrets, and full compromise.
- Traffic/request inspection is essential in web CTF challenges.
