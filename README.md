# Living Off The Land Certificates (LoLCerts)

Threat actors are known to sign their malware using either stolen or legally acquired code signing certificates. This threat is becoming more relevant as more and more defenses are relying on digital signatures for allowing or not execution on an endpoint. This project aims at collecting the details of the certificates that are known to be abused in the wild by malicious actors.

The `scripts` directory contains a Python script used to generate Yara rules for all the certificates.
Rules are written according to [Nextron System - Short tutorial how to create a yara rule for a compromised certificate](https://www.nextron-systems.com/2018/11/01/short-tutorial-how-to-create-a-yara-rule-for-a-compromised-certificate/).

To generate all the yara rules:

```
cd scripts/
python3 generate_yara.py
```

Schema:
```yml
name: name_of_the_certificate
meta:
  status: revoked|valid
  source: leaked|malicious
  description: |
    Brief description of the certificate and where was it obtained from
  references: Threat intelligence reference
  date: Date of release
  author: Author Name
issuer: Issuer of the certificate
timestamp: Unix timestamp of when the cert was leaked, if relevant
serial: Array of strings containing the serial numbers of the certificates
thumbprint: Optional array of strings containing the thumbprints of the certificates
```