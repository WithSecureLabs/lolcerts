# Living Off The ~~Land~~Leaked Certificates (LoLCerts)
Threat actors often employ stolen or legally acquired code signing certificates to sign their malware. This threat has gained significance as digital signatures play a crucial role in endpoint security. This project focuses on gathering details about certificates known to be misused by malicious actors in the wild.

## Table of Contents
- [Introduction](#living-off-the-land-leaked-certificates-lolcerts)
- [Usage](#usage)
- [Schema](#schema)
- [Credits](#credits)
- [Licenses](#licenses)

## Usage
"Living Off The Leaked Certificates (LoLCerts)" is a project designed to track and document instances of code signing certificates being misused by threat actors. By collecting and organizing details about these abused certificates, security professionals can enhance their threat intelligence and strengthen defenses against malware. The provided Python script generates YARA rules based on the collected information, enabling users to proactively identify and mitigate potential security risks associated with compromised certificates. Run the commands below to use this project.

The `scripts` directory contains a Python script used to generate Yara rules for all the collected certificates. Rules are crafted following the guidelines in the [Nextron System - Short tutorial on creating a Yara rule for a compromised certificate](https://www.nextron-systems.com/2018/11/01/short-tutorial-how-to-create-a-yara-rule-for-a-compromised-certificate/).

Commands to generate all the Yara rules:
```bash
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

## Credits
We acknowledge the following contributors to the project:
- [Contributor 1](https://github.com/dottor_morte)
- [Contributor 2](https://github.com/RiccardoAncarani)
- [Contributor 3](https://github.com/BrookeScoglio)
- [Nextron Systems](https://www.nextron-systems.com/)

## Licenses
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.