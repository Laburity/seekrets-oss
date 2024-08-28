<h1 align="center">
  <br>
  <a href="https://github.com/Laburity/seekrets-oss"><img src="https://i.ibb.co/JQpyNwC/Transparent-PNG-file.png" height="200" width="600" alt="Seekrets"></a>
  <br>
  Seekrets
  <br>
</h1>

<h4 align="center">A basic Secret Scanning tool</h4>

# seekrets-oss

Seekerts - A Supply Chain Secret Scanning tool that detects hidden secrets inside code ;)

## Description

A supply chain secret scanning tool designed to detect  secrets and sensitive information embedded within the codebase. Enhance your security posture by identifying credentials, API keys, and other confidential data before they become vulnerabilities.

## Requirements

```
Requests==2.32.3
urllib3==2.2.2
```

## Dependencies

```
nuclei 
nuclei-templates
```

Make sure you have installed nuclei and you also have nuclei templates that exists in `~/nuclei-templates/`

## Usage 

```
usage: seekrets.py [-h] [-n NPMJS] [-z ZIPF]

Perform Secret Scanning on NPM JS Modules & Zip Files

options:
  -h, --help            show this help message and exit
  -n NPMJS, --npmjs NPMJS
                        Choose any NPM JS package name e.g express
  -z ZIPF, --zipf ZIPF  Select a ZIP file e.g file.zip
```

## Seekrets.py

```
python3 seekrets.py --npmjs redacted-package
Downloading redacted-package
Downloaded redacted-package.tgz
Extracting redacted-package to extracted/redacted-package...
Extracted redacted-package to extracted/redacted-package
Cleaned up: removed redacted-package.tgz
Running Secret scan on extracted/redacted-package...
Secret scan completed successfully.

Scan Results:
Signature: [basic-auth-creds]
Protocol: [file]
Severity: [high]
Affected File: extracted/redacted-package/package/.env
Exposure: "postgresql://postgres:redacted.@redacted:5432/redacted?schema=public&connection_limit=5""
--------------------------------------------------

Signature: [basic-auth-creds]
Protocol: [file]
Severity: [high]
Affected File: extracted/redacted-package/package/.env.dev
Exposure: "postgresql://johndoe:redacted@localhost:5432/mydb?schema=public""
```

