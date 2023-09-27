<h1 align="center"><a href="https://github.com/h4r5h1t/CertCheck.git">CertCheck</a></h1>
<h4 align="center">A Python tool to check and validate SSL/TLS certificates for common misconfigurations and output the results in JSON format.</h4>

<p align="center">
<a href="https://twitter.com/h4r5h1t_hrs"><img src="https://img.shields.io/twitter/follow/h4r5h1t_hrs?style=social"></a>
<a href="https://github.com/h4r5h1t?tab=followers"><img src="https://img.shields.io/github/followers/h4r5h1t?style=social"></a>
<a href="https://github.com/h4r5h1t/CertCheck/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/h4r5h1t/CertCheck/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
<a href="#"><img src="https://img.shields.io/badge/Made%20with-Python-1f425f.svg"></a>
<a href="#"><img src="https://madewithlove.now.sh/in?heart=true"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
</p>

This Python tool checks the expiration date and other information of a website's SSL/TLS certificate. It uses asyncio and SSLContext to make secure connections to websites and obtain SSL certificate information. The tool validates the SSL/TLS certificate for common misconfigurations like Expired Certificates, Self-signed Certificates, Mismatched Certificates, Revoked Certificates, and outputs the SSL/TLS certificate information in a formatted JSON object.

## Features
- Checks the expiration date and other information of a website's SSL/TLS certificate
- Uses asyncio and SSLContext to make secure connections to websites and obtain SSL certificate information
- Validates SSL/TLS certificate for common misconfigurations like:
  - Expired Certificates,
  - Self-signed Certificates,
  - Mismatched Certificates, and
  - Revoked Certificates
- Outputs the SSL/TLS certificate information in a formatted JSON object including:
  - A boolean indicating if the certificate is valid or not
  - An error message if the certificate is not valid
  - The date the certificate was issued
  - The date the certificate expires
  - The number of days until the certificate expires
  - The subject of the certificate
  - The issuer of the certificate
  - The subject alternative names of the certificate
  - The serial number of the certificate
  - The version of the certificate
  - The signature algorithm of the certificate

## Installation

```bash
git clone https://github.com/h4r5h1t/CertCheck.git
cd CertCheck
pip install .
```

# Usage
To run the program, use the following command:
```bash
certcheck --help
```
This will display the following output:
```bash
usage: certcheck [-h] -u URL [URL ...] [-o OUTPUT] [--debug]

A simple python script to check and validate the SSL/TLS certificate information of a website.

options:
  -h, --help            show this help message and exit
  -u URL [URL ...], --url URL [URL ...]
                        Provide URL or list of URLs to check
  -o OUTPUT, --output OUTPUT
                        In addition to STDOUT also write results to file.
  --debug               Enable debug mode

Example: certcheck -u https://example.com [-o output.txt] [--debug]
```

To check the SSL/TLS Certificate information of a single URL, use the '-u' flag and provide the URL as an argument:
```bash
certcheck -u https://example.com
```

To check the SSL/TLS Certificate information of multiple URLs, provide a list of URLs separated by spaces:
```bash
certcheck -u https://example.com https://google.com https://apple.com
```

To save the results to a file, use the '-o' flag and provide the file path as an argument:
```bash
certcheck -u https://example.com -o output.txt
```

To enable debug mode, use the '--debug' flag:
```bash
certcheck -u https://example.com --debug
```

<table>
<td>
<b>Warning:</b> Developers assume no liability and are not responsible for any misuse or damage cause by this tool. So, please se with caution because you are responsible for your own actions.
</td>
</table>