#!/usr/bin/env python3
"""
A simple python script to check and validate the SSL/TLS certificate information of a website.
"""

import os
import ssl
import datetime
import json
import asyncio
from typing import List, Dict
from argparse import ArgumentParser, ArgumentError
import OpenSSL
from ocspchecker import ocspchecker
from furl import furl

async def get_ssl_info(hostname, port, debug:bool=False):
    """
    Get the SSL certificate information.

    Args:
        hostname (str): The domain name of the website
        port (int): The port number of the website
        debug (bool): Print debug messages

    Returns:
        dict: A dictionary containing the SSL certificate information
    """
    ssl_info = None
    try:
        # Create an SSL context
        context = ssl.create_default_context()
        _, writer = await asyncio.wait_for(asyncio.open_connection(hostname, port, ssl=context), timeout=10)
        ssl_info = writer.get_extra_info('peercert')
        writer.close()
        await writer.wait_closed()
    except ssl.SSLError as ssl_error:
        # Print an error message
        if debug:
            print(ssl_error)
    except asyncio.TimeoutError as timeout_error:
        # Print an error message
        if debug:
            print(timeout_error)
    return ssl_info

async def check_ssl_validity(ssl_info, hostname:str, port:int) -> dict:
    """
    Check the validity of an SSL/TLS certificate.
        - Check if the SSL/TLS certificate has expired or is not yet valid
        - Check if the SSL/TLS certificate is mismatched
        - Check if the SSL/TLS certificate is self-signed
        - Check if the SSL/TLS certificate is revoked

    Args:
        ssl_info (dict): A dictionary containing the SSL certificate information
        hostname (str): The domain name of the website
        port (int): The port number of the website

    Returns:
        dict: A dictionary containing the results of the SSL certificate check
    """
    results = {}

    if ssl_info is None:
        results["valid"] = False
        results["error"] = "The domain does not have a valid SSL/TLS certificate."
        return results

    now = datetime.datetime.utcnow() # Get the current date and time
    if "notAfter" in ssl_info:
        # Check if the SSL certificate has expired or is not yet valid
        not_after = datetime.datetime.strptime(ssl_info["notAfter"], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.datetime.strptime(ssl_info["notBefore"], '%b %d %H:%M:%S %Y %Z')
        if now > not_after:
            results["valid"] = False
            results["error"] = "The SSL/TLS certificate has expired."
            return results
        elif now < not_before:
            results["valid"] = False
            results["error"] = "The SSL/TLS certificate is not yet valid."
            return results
        else:
            results["issued_date"] = not_before.strftime("%Y-%m-%d %H:%M:%S")
            results["expiration_date"] = not_after.strftime("%Y-%m-%d %H:%M:%S")
            results["days_until_expiration"] = (not_after - now).days

    try:
        # Check if the SSL certificate matches the domain name
        ssl.match_hostname(ssl_info, hostname)
    except ssl.SSLCertVerificationError:
        results["valid"] = False
        results["error"] = "The SSL/TLS certificate does not match the domain name."
        return results

    try:
        certificate = ssl.get_server_certificate((hostname, port))
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        #extracting the data from certificate
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        ssl_context.load_verify_locations(cadata=certificate)
        _, writer = await asyncio.open_connection(hostname, port, ssl=ssl_context)
        writer.close()
        await writer.wait_closed()

        # Check if the SSL certificate is revoked
        ocsp_request = ocspchecker.get_ocsp_status(hostname)
        if ocsp_request and 'OCSP Status: GOOD' in ocsp_request:
            pass
        else:
            results["valid"] = False
            results["error"] = "The SSL/TLS certificate is revoked."
            return results

    except ssl.SSLError as error_code:
        if 'unknown' in str(error_code).lower():
            results["valid"] = False
            results["error"] = "The SSL/TLS certificate is not trusted."
        else:
            results["valid"] = False
            results["error"] = "An error occurred while checking the SSL/TLS certificate."
        return results

    if x509:
        if x509.get_issuer().CN == x509.get_subject().CN:
            results["valid"] = False
            results["error"] = "The SSL/TLS certificate is self-signed."
            return results

    results["valid"] = True
    results["x509"] = x509
    return results

def format_results(results:dict, ssl_info:dict) -> dict:
    """
    Format the results of the certificate check.

    Args:
        result (dict): A dictionary containing the results of the certificate check
        ssl_info (dict): A dictionary containing the SSL certificate information

    Returns:
        dict: A dictionary containing the results of the certificate check
    """
    x509 = results.pop("x509")
    if x509:
        subject = x509.get_subject()
        results["subject"] = {}
        results["subject"]["country_name"] = subject.C
        results["subject"]["state_or_province_name"] = subject.ST
        results["subject"]["locality_name"] = subject.L
        results["subject"]["organization_name"] = subject.O
        results["subject"]["organizational_unit_name"] = subject.OU
        results["subject"]["common_name"] = subject.CN

        issuer = x509.get_issuer()
        results["issuer"] = {}
        results["issuer"]["country_name"] = issuer.C
        results["issuer"]["state_or_province_name"] = issuer.ST
        results["issuer"]["locality_name"] = issuer.L
        results["issuer"]["organization_name"] = issuer.O
        results["issuer"]["organizational_unit_name"] = issuer.OU
        results["issuer"]["common_name"] = issuer.CN

        if "subjectAltName" in ssl_info:
            results["subject_alt_names"] = [name for _, name in ssl_info["subjectAltName"]]

        results["serial_number"] = x509.get_serial_number()
        results["version"] = x509.get_version()
        results["signature_algorithm"] = x509.get_signature_algorithm().decode("utf-8")

    return results

def validate_url(url:str) -> str|None:
    """
    Validate the URL.

    Args:
        url (str): The URL to validate

    Returns:
        str: The validated URL
    """
    if url.startswith("http://"):
        return None
    if not url.startswith("https://"):
        url = "https://" + url
    return url

# pylint: disable=C0103, C0301
async def check_certificate(url:str, debug:bool=False) -> dict:
    """
    Get the SSL/TLS certificate information for a website.

    Args:
        url (str): The URL of the website to check
        debug (bool): Enable debug mode

    Returns:
        dict: A dictionary containing the results of the certificate check, including:
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
    """
    try:
        # Check if the URL is valid
        valid_url = validate_url(url)
        if not valid_url:
            if debug:
                print("The URL is using HTTP. HTTPS is required.")
            return {
                url: {
                    "valid": False,
                    "error": "The URL is using HTTP. HTTPS is required."
                }
            }

        # Get the hostname and port from the URL
        hostname:str = furl(valid_url).host
        port:int = furl(valid_url).port if furl(valid_url).port else 443

        if debug:
            print(f"Checking SSL/TLS certificate information for {hostname} on port {port}...")

        # Get the SSL certificate info
        ssl_info = await get_ssl_info(hostname, port, debug=debug)
        # Check if the certificate is valid
        result = await check_ssl_validity(ssl_info, hostname, port)

        # If the certificate is not valid, return an error message
        if not result["valid"]:
            if debug:
                print(result["error"])
            return {url: result}

        # If the certificate is valid, return the results
        if debug:
            print(f"The SSL/TLS certificate for {hostname} expires in {result['days_until_expiration']} days.")

        return {url: format_results(result, ssl_info)}

    except Exception as err:
        # If an error occurs print the error message and return an empty dictionary
        if debug:
            print(err)

        return {
            url:{}
        }

def parse_args() -> ArgumentParser:
    """
    Parse the command line arguments.
    """
    # Initialize the argument parser
    parser = ArgumentParser(
        prog = "certcheck",
        description="A simple python script to check and validate the SSL/TLS certificate information of a website.",
        epilog="Example: python certcheck -u https://example.com [-o output.txt] [--debug]"
    )
    parser.add_argument("-u", "--url", type=str, nargs='+', dest="url", help="Provide URL or list of URLs to check", required=True)
    parser.add_argument("-o", "--output", type=str, dest="output", default=None, help="In addition to STDOUT also write results to file.")
    parser.add_argument("--debug", action="store_true", dest="debug", help="Enable debug mode")
    return parser.parse_args()

async def main():
    """
    Main function.
    """
    try:
        # Parse the command line arguments
        args: ArgumentParser = parse_args()

        # Initialize an empty list and dict to store the results
        output_list: List[str] = []
        output: Dict[str, dict] = {}

        # Check if the URL argument was provided
        if args.url:
            # Check the certificate and append the results to the output list
            output_list = await asyncio.gather(*[check_certificate(url.strip(), debug=args.debug) for url in args.url])

        else:
            # If the URL argument was not provided, print an error message and exit
            print("No URL was provided. Please provide a URL or list of URLs to check.")
            return

        if output_list:
            # Convert the list of dictionaries to a single dictionary
            output = {url: info for d in output_list for url, info in d.items()}

        # Print the results
        print(json.dumps(output, indent=3))

        # Save the results to a JSON
        if args.output:
            with open(os.path.join(os.getcwd(), args.output), "w", encoding="utf-8") as f:
                json.dump(output, f, indent=3)
                if args.debug:
                    print(f"Saved the results to a JSON file. Location: {os.path.join(args.output, 'output.json')}")

    except ArgumentError as arg_err:
        print(arg_err)
    except Exception as exp:
        print(exp)
