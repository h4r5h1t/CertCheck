#Add root path to sys.path
import sys
sys.path.insert(0, '.')
import pytest
from certcheck.certcheck import *

# import asyncio
# import unittest
# from mock import patch

@pytest.mark.asyncio
async def test_check_certificate_valid():
    url = "https://www.google.com"
    result = await check_certificate(url)
    assert isinstance(result, dict)
    assert result[url]
    assert all(key in result[url] 
        for key in ('issued_date', 'expiration_date', 'days_until_expiration', 'valid', 'subject', 'issuer', 'subject_alt_names', 'serial_number', 'version', 'signature_algorithm')
    )
    assert result[url]["valid"] == True

@pytest.mark.asyncio
async def test_check_certificate_invalid():
    url = "https://expired.badssl.com"
    result = await check_certificate(url)
    assert result[url]
    assert result[url]["valid"] == False
    assert result[url]["error"] == "The domain does not have a valid SSL/TLS certificate."

def test_validate_url():
    assert validate_url("https://www.google.com") == "https://www.google.com"
    assert validate_url("www.google.com") == "https://www.google.com"
    assert validate_url("google.com") == "https://google.com"
    assert validate_url("http://www.google.com") is None


# class TestCertCheck(unittest.TestCase):
#     def test_get_ssl_info(self):
#         loop = asyncio.get_event_loop()
#         result = loop.run_until_complete(get_ssl_info('google.com', 443))
#         self.assertIsInstance(result, dict)
#         self.assertIn('subject', result)
#         self.assertIn('issuer', result)
#         self.assertIn('notBefore', result)
#         self.assertIn('notAfter', result)
#         self.assertIn('subjectAltName', result)
# @patch('ssl.get_server_certificate')
# @pytest.mark.asyncio
# async def test_check_certificate_misconfigured(mock_get_server_certificate):
#     url = "https://expired.badssl.com"
#     mock_get_server_certificate.return_value = "misconfigured"
#     result = await check_certificate(url)
#     assert result[url]["misconfigured"] == True
    
