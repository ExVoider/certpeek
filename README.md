# certpeek

A small CLI tool to inspect TLS certificate information for a domain.

## Features

- Fetch TLS certificate from a domain
- Show certificate subject and issuer
- Display validity period
- Calculate days until expiry
- Show expiry status
- Show SHA256 certificate fingerprint
- List Subject Alternative Names (SAN)
- Show TLS protocol and authorization status

## Installation

```bash
git clone https://github.com/ExVoider/certpeek.git
cd certpeek
```

## Usage

```
node certpeek.js google.com
node certpeek.js google.com 443
```

## Example

```
node certpeek.js github.com 443
```
Example output:

```
Host: github.com
Port: 443

TLS
---
Authorized : true
TLS Version: TLSv1.3
Auth Error : None

Certificate Info
----------------
Subject            : CN=github.com
Issuer             : CN=Sectigo ECC Domain Validation Secure Server CA
Valid From         : May 1 00:00:00 2026 GMT
Valid Until        : May 1 23:59:59 2027 GMT
Days Left          : 320
Expiry Status      : Healthy
Serial Number      : 1234567890
SHA256 Fingerprint : AB:CD:EF:...

SAN Names
---------
DNS:github.com
DNS:www.github.com
```
