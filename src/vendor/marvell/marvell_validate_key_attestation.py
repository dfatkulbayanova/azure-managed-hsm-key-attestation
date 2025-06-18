# MIT License

# Copyright (c) Microsoft Corporation.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE

from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Optional, Set, Tuple
from cryptography.x509 import Certificate

import hashlib
import argparse
import pem

from termcolor import colored

# You can download the certificate from the marvell website and validate the following certificate is same. 
# https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/liquidsecurity-certificate-cnxxxxx-nfbe-x0-g-v3.html
MARVELL_HSM_ROOT_CERTIFICATE = '''Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = California, L = San Jose, O = "Cavium, Inc.", OU = LiquidSecurity, CN = localca.liquidsecurity.cavium.com
        Validity
            Not Before: Jul 25 20:29:20 2024 GMT
            Not After : Jul 23 20:29:20 2034 GMT
        Subject: C = US, ST = California, L = San Jose, O = "Cavium, Inc.", OU = LiquidSecurity, CN = localca.liquidsecurity.cavium.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:dc:92:fa:90:33:87:2f:66:37:72:a8:e2:c6:31:
                    38:ca:27:0b:df:c4:93:a1:56:ac:3a:a6:88:e0:50:
                    cc:f5:d1:55:3b:cf:70:ad:26:bc:07:70:44:b0:10:
                    35:31:52:43:31:ce:87:f9:e6:41:68:ad:44:4b:69:
                    55:42:8d:e7:58:6a:e1:22:b2:76:70:c1:25:a4:01:
                    e9:a9:f4:64:44:9b:c8:97:e8:15:ed:a1:9f:15:0d:
                    6a:0e:d8:7d:00:26:21:c2:33:ad:aa:25:e6:55:5e:
                    19:bc:03:fc:d6:1b:43:f2:2e:b0:88:34:7d:32:cf:
                    d6:a1:e8:17:30:76:c6:46:2e:f4:2f:92:95:0d:26:
                    1c:15:32:b6:fd:9c:8f:41:95:19:93:5a:1a:28:b7:
                    56:12:4d:fe:e3:7e:26:c4:91:cf:e9:37:ed:04:cf:
                    7d:11:15:a2:f7:32:1c:88:68:d2:52:db:6f:b5:d2:
                    d9:f2:e2:c3:94:4e:c3:c4:b5:72:9a:87:99:8f:94:
                    7a:67:ac:67:01:d7:cc:f9:63:18:2b:d2:f0:cd:63:
                    1f:85:08:f1:a8:f7:95:c6:ae:af:4d:61:f3:4c:97:
                    0b:12:78:54:ab:f0:3d:55:43:b1:d9:9a:2a:5e:4c:
                    1d:61:41:35:10:c3:f2:bf:46:6b:70:e4:d8:a5:8e:
                    46:13
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign
            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         98:96:be:da:79:39:db:45:f3:c9:19:ce:50:e4:b1:15:ad:e6:
         3d:d6:6a:74:7b:92:8d:df:7d:62:1b:70:d7:43:ac:74:ed:13:
         18:e0:f3:cd:f8:cb:d5:80:83:c3:db:52:31:e9:7b:69:e9:58:
         fd:55:cb:01:a5:5e:e1:fb:a5:fa:f6:ce:fd:23:1f:23:d1:75:
         7e:eb:e0:27:ac:bb:9f:b6:35:23:37:0e:e2:23:db:21:39:86:
         bd:69:24:e0:fd:1e:98:a7:0c:29:5c:7f:8b:dd:26:59:f9:51:
         05:c8:18:39:80:ce:da:cf:46:89:be:e1:78:f1:f4:b1:34:dc:
         1e:97:5d:55:0b:ac:64:ad:41:53:bb:32:35:dc:6a:98:7b:ed:
         ab:5a:17:3f:e1:35:af:b3:53:e9:4b:30:34:2b:45:bb:29:81:
         57:da:38:46:8b:b1:f5:b8:ea:d5:9d:e2:62:69:58:03:f5:b8:
         08:6a:8f:d4:69:06:9b:8e:52:d3:eb:6c:04:f4:37:a0:a5:d2:
         8f:38:76:c8:89:0a:79:5c:e5:75:ac:83:ff:a4:05:92:4a:2c:
         98:ec:10:7b:73:56:9c:0b:fd:ee:70:3a:12:8d:33:54:12:c5:
         48:93:76:6c:9b:68:e2:53:2d:17:0b:fa:d9:4f:16:99:90:76:
         87:06:ec:7b
-----BEGIN CERTIFICATE-----
MIIDvzCCAqegAwIBAgIBADANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQK
DAxDYXZpdW0sIEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQD
DCFsb2NhbGNhLmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wHhcNMjQwNzI1MjAy
OTIwWhcNMzQwNzIzMjAyOTIwWjCBkTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh
bGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQKDAxDYXZpdW0sIElu
Yy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQDDCFsb2NhbGNhLmxp
cXVpZHNlY3VyaXR5LmNhdml1bS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDckvqQM4cvZjdyqOLGMTjKJwvfxJOhVqw6pojgUMz10VU7z3CtJrwH
cESwEDUxUkMxzof55kForURLaVVCjedYauEisnZwwSWkAemp9GREm8iX6BXtoZ8V
DWoO2H0AJiHCM62qJeZVXhm8A/zWG0PyLrCINH0yz9ah6BcwdsZGLvQvkpUNJhwV
Mrb9nI9BlRmTWhoot1YSTf7jfibEkc/pN+0Ez30RFaL3MhyIaNJS22+10tny4sOU
TsPEtXKah5mPlHpnrGcB18z5Yxgr0vDNYx+FCPGo95XGrq9NYfNMlwsSeFSr8D1V
Q7HZmipeTB1hQTUQw/K/Rmtw5NiljkYTAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIC
hDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCYlr7aeTnbRfPJGc5Q
5LEVreY91mp0e5KN331iG3DXQ6x07RMY4PPN+MvVgIPD21Ix6Xtp6Vj9VcsBpV7h
+6X69s79Ix8j0XV+6+AnrLuftjUjNw7iI9shOYa9aSTg/R6YpwwpXH+L3SZZ+VEF
yBg5gM7az0aJvuF48fSxNNwel11VC6xkrUFTuzI13GqYe+2rWhc/4TWvs1PpSzA0
K0W7KYFX2jhGi7H1uOrVneJiaVgD9bgIao/UaQabjlLT62wE9DegpdKPOHbIiQp5
XOV1rIP/pAWSSiyY7BB7c1acC/3ucDoSjTNUEsVIk3Zsm2jiUy0XC/rZTxaZkHaH
Bux7
-----END CERTIFICATE-----'''
# You can retrieve the certificate from the marvell website and validate the following certificate is same.
# https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/liquidsecurity2-certificate-ls2-g-axxx-mi-f-bo-v2.html.
# Please look for the file name: mrvl-rsa-LS2-MI.crt
MARVELL_LS2_HSM_ROOT_CERTIFICATE = '''Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US + ST = CA + OU = SSBU + L = SanJose + O = Marvell, CN = cavium-liquidsecurity-ls2
        Validity
            Not Before: Jul 22 20:34:23 2024 GMT
            Not After : Jul 20 20:34:23 2034 GMT
        Subject: C = US + ST = CA + OU = SSBU + L = SanJose + O = Marvell, CN = cavium-liquidsecurity-ls2
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:cf:31:f0:92:4f:2e:25:0b:53:39:66:9c:32:93:
                    42:91:6f:83:48:b2:e4:66:a3:8f:b5:6d:39:4d:38:
                    b2:cc:ce:57:17:05:58:ce:1a:50:88:46:c6:ae:db:
                    6c:ab:57:ed:2c:4c:8a:e4:7b:c1:f4:88:91:35:be:
                    3b:90:11:de:41:be:3f:18:4f:2b:27:1f:29:a0:12:
                    d0:74:ce:df:c7:91:98:8d:6a:f7:81:36:ea:0f:e4:
                    9f:8f:ba:1f:c1:02:58:e7:11:9b:55:31:36:58:c4:
                    24:db:07:73:a3:42:c3:73:68:b5:51:5f:79:fb:c4:
                    62:0a:63:d8:d4:b9:44:67:16:b3:d2:1c:3e:15:df:
                    cf:bb:84:74:0e:b4:b5:a1:1d:ca:1b:ea:7a:da:0f:
                    42:86:14:28:5a:56:07:7b:ae:84:e5:ee:61:4b:8d:
                    ca:25:ea:0d:e9:ba:40:b1:b5:ce:57:3b:75:af:6d:
                    67:d1:ff:c5:96:54:c1:f8:4f:c4:36:21:8b:b8:fa:
                    3d:06:e0:6e:8a:24:37:f7:2c:54:2d:bd:b4:d8:ad:
                    4d:9f:02:28:53:f1:2e:81:83:24:c2:82:a1:5f:3b:
                    2a:7f:54:71:ef:10:eb:ee:b1:ee:e1:af:9e:0a:49:
                    bb:34:e4:b1:7e:c5:eb:d8:44:3c:0f:aa:c2:63:ee:
                    e7:e3:5c:cd:ac:4d:1e:d8:1f:7d:cb:0c:fb:56:28:
                    cf:41:c9:17:b1:10:c1:76:fc:79:24:fb:db:d6:3b:
                    28:73:85:fe:b3:0e:bf:7a:42:a4:a5:48:56:93:2b:
                    95:f3:d9:ac:8b:1f:f2:91:0c:0c:a1:8a:c8:79:d9:
                    db:b5:72:77:56:30:90:71:8b:a7:0e:68:12:c6:dc:
                    b6:5c:f3:d1:86:ca:9e:d8:f9:b2:b4:e8:41:f9:51:
                    8f:ff:06:6f:6e:d6:e1:28:05:27:c1:69:69:39:cd:
                    9c:7a:c4:49:42:ab:5e:01:60:7d:28:40:ef:03:99:
                    6d:d3:f3:80:d6:d1:0f:59:1d:7a:9b:6a:ca:9c:17:
                    62:bd:8e:1a:5a:a2:75:64:45:b6:84:2c:2e:39:b2:
                    f8:33:bb:fd:8f:13:d0:ac:c8:e5:6a:4d:a5:2d:9f:
                    c4:ff:c9:95:6d:3b:d2:60:96:d0:19:af:31:90:72:
                    f5:06:ab:26:38:70:39:62:83:da:54:6a:0d:60:a4:
                    82:e4:49:a6:32:a7:2c:15:14:8e:39:c1:59:0b:89:
                    9c:56:1c:2e:e3:35:20:6b:c8:06:14:72:32:eb:ec:
                    ba:ff:a2:c0:dc:1a:6c:86:80:7d:f6:f9:e4:d2:b9:
                    da:34:7a:f7:95:cd:e7:7f:d5:aa:b5:bf:18:65:d5:
                    45:b5:db
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign
            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         8d:77:22:5e:59:32:32:39:0e:a6:ca:64:58:b5:ae:6d:5d:fc:
         c8:74:15:13:d3:54:58:4a:42:e6:b0:28:1a:b0:b6:d2:1c:06:
         65:ab:c1:ce:c2:6a:33:12:bf:19:2f:7f:5f:d8:14:3b:f7:c5:
         45:1e:f1:f0:b2:32:49:55:b2:4d:63:a6:3d:0a:65:de:86:cb:
         0f:5b:11:65:35:84:d7:8f:83:f8:18:87:af:a7:5f:52:b7:d5:
         54:d5:df:5a:95:38:58:0f:23:fb:64:74:d9:84:ca:2a:95:97:
         ef:a9:84:3a:a7:37:6f:23:e4:7e:f6:f8:47:ba:61:0d:9f:c3:
         66:d0:70:73:ee:5c:1c:d2:bc:0c:d4:ba:67:7e:a0:f6:93:f7:
         66:0a:4d:71:f7:8d:de:e6:8f:91:ce:2e:e4:63:39:b8:fa:08:
         ed:68:47:ed:6e:f4:d7:e4:56:7f:8d:3a:6f:74:e3:a4:1a:fe:
         74:92:7d:fb:24:76:91:ff:e1:49:c0:49:98:40:46:ec:b7:b8:
         55:ca:4c:90:3b:f1:49:d3:0b:64:16:48:cd:0e:93:ea:43:24:
         de:b9:6a:40:79:39:fc:c5:87:bc:cd:9f:14:1a:2a:25:a8:51:
         89:3b:64:a2:98:b2:13:0a:c6:e8:7e:81:14:9e:76:2b:e0:7a:
         7b:cf:83:75:bd:92:1b:83:ae:46:bd:54:dd:a3:c6:de:f0:80:
         f3:00:aa:ca:dd:f3:0e:4f:ec:ec:2a:36:86:3e:15:42:bc:c3:
         9b:7e:ed:f0:fb:24:3a:5e:89:fc:f3:9d:01:5c:89:10:6e:2c:
         ee:2e:9a:c4:5b:f4:f0:85:33:00:b5:ae:0d:d5:ce:6b:18:44:
         1f:ec:4c:34:36:e3:b7:90:6c:80:35:6b:9b:eb:76:73:00:c6:
         8b:08:9f:21:44:a8:7a:55:d6:ed:17:5e:84:fd:28:63:99:bb:
         d7:5d:5e:8e:d1:28:39:07:cd:65:ec:76:9d:b3:c6:7f:0d:63:
         53:62:9a:b2:b7:83:2a:5b:4e:36:f7:ed:f5:57:06:65:7b:8c:
         ab:c9:5f:1b:7e:c4:62:ed:88:fb:63:41:54:c4:24:18:78:d7:
         34:cc:9f:ba:18:31:db:11:6e:43:f8:30:76:4b:b2:b2:77:82:
         0a:d9:61:20:e8:72:59:59:2d:84:33:af:a8:54:43:bd:74:18:
         0a:38:05:4c:64:be:f8:a3:39:61:45:2e:e6:ef:cd:e6:86:d4:
         8d:cc:39:c9:7b:60:c7:69:3a:1f:ca:d0:89:15:67:88:9e:d3:
         2f:97:b2:96:96:32:3d:2c:16:89:dc:f7:33:15:f8:36:6f:42:
         1b:90:51:3f:84:c2:48:b0
-----BEGIN CERTIFICATE-----
MIIFbTCCA1WgAwIBAgIBADANBgkqhkiG9w0BAQsFADBpMUMwCQYDVQQGEwJVUzAJ
BgNVBAgMAkNBMAsGA1UECwwEU1NCVTAOBgNVBAcMB1Nhbkpvc2UwDgYDVQQKDAdN
YXJ2ZWxsMSIwIAYDVQQDDBljYXZpdW0tbGlxdWlkc2VjdXJpdHktbHMyMB4XDTI0
MDcyMjIwMzQyM1oXDTM0MDcyMDIwMzQyM1owaTFDMAkGA1UEBhMCVVMwCQYDVQQI
DAJDQTALBgNVBAsMBFNTQlUwDgYDVQQHDAdTYW5Kb3NlMA4GA1UECgwHTWFydmVs
bDEiMCAGA1UEAwwZY2F2aXVtLWxpcXVpZHNlY3VyaXR5LWxzMjCCAiIwDQYJKoZI
hvcNAQEBBQADggIPADCCAgoCggIBAM8x8JJPLiULUzlmnDKTQpFvg0iy5Gajj7Vt
OU04sszOVxcFWM4aUIhGxq7bbKtX7SxMiuR7wfSIkTW+O5AR3kG+PxhPKycfKaAS
0HTO38eRmI1q94E26g/kn4+6H8ECWOcRm1UxNljEJNsHc6NCw3NotVFfefvEYgpj
2NS5RGcWs9IcPhXfz7uEdA60taEdyhvqetoPQoYUKFpWB3uuhOXuYUuNyiXqDem6
QLG1zlc7da9tZ9H/xZZUwfhPxDYhi7j6PQbgbookN/csVC29tNitTZ8CKFPxLoGD
JMKCoV87Kn9Uce8Q6+6x7uGvngpJuzTksX7F69hEPA+qwmPu5+NczaxNHtgffcsM
+1Yoz0HJF7EQwXb8eST729Y7KHOF/rMOv3pCpKVIVpMrlfPZrIsf8pEMDKGKyHnZ
27Vyd1YwkHGLpw5oEsbctlzz0YbKntj5srToQflRj/8Gb27W4SgFJ8FpaTnNnHrE
SUKrXgFgfShA7wOZbdPzgNbRD1kdeptqypwXYr2OGlqidWRFtoQsLjmy+DO7/Y8T
0KzI5WpNpS2fxP/JlW070mCW0BmvMZBy9QarJjhwOWKD2lRqDWCkguRJpjKnLBUU
jjnBWQuJnFYcLuM1IGvIBhRyMuvsuv+iwNwabIaAffb55NK52jR695XN53/VqrW/
GGXVRbXbAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIChDAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4ICAQCNdyJeWTIyOQ6mymRYta5tXfzIdBUT01RYSkLmsCga
sLbSHAZlq8HOwmozEr8ZL39f2BQ798VFHvHwsjJJVbJNY6Y9CmXehssPWxFlNYTX
j4P4GIevp19St9VU1d9alThYDyP7ZHTZhMoqlZfvqYQ6pzdvI+R+9vhHumENn8Nm
0HBz7lwc0rwM1LpnfqD2k/dmCk1x943e5o+Rzi7kYzm4+gjtaEftbvTX5FZ/jTpv
dOOkGv50kn37JHaR/+FJwEmYQEbst7hVykyQO/FJ0wtkFkjNDpPqQyTeuWpAeTn8
xYe8zZ8UGiolqFGJO2SimLITCsbofoEUnnYr4Hp7z4N1vZIbg65GvVTdo8be8IDz
AKrK3fMOT+zsKjaGPhVCvMObfu3w+yQ6Xon8850BXIkQbizuLprEW/TwhTMAta4N
1c5rGEQf7Ew0NuO3kGyANWub63ZzAMaLCJ8hRKh6VdbtF16E/ShjmbvXXV6O0Sg5
B81l7Hads8Z/DWNTYpqyt4MqW0429+31VwZle4yryV8bfsRi7Yj7Y0FUxCQYeNc0
zJ+6GDHbEW5D+DB2S7Kyd4IK2WEg6HJZWS2EM6+oVEO9dBgKOAVMZL74ozlhRS7m
783mhtSNzDnJe2DHaTofytCJFWeIntMvl7KWljI9LBaJ3PczFfg2b0IbkFE/hMJI
sA==
-----END CERTIFICATE-----'''

ATTESTATION_SIGNATURE_SIZE: int = 256

def find_issued_certificate(certificate_list: Set[pem.AbstractPEMObject], verbose: bool = False, *signer_certificate_obj_list: Tuple[x509.Certificate, ...]) -> Optional[x509.Certificate]:
    for cert in certificate_list:
        cert_utf8_encoded: bytes = cert.as_text().encode("utf-8")
        cert_object: x509.Certificate = x509.load_pem_x509_certificate(cert_utf8_encoded, backends.default_backend())
        for signer_certificate_obj in signer_certificate_obj_list:
            if cert_object.issuer != cert_object.subject and cert_object.issuer == signer_certificate_obj.subject:
                try:
                    signer_certificate_obj.public_key().verify(
                        cert_object.signature,
                        cert_object.tbs_certificate_bytes,
                        padding.PKCS1v15(), # CodeQL [SM04457] The PKCS1v15 padding is used for RSA signature verification as required by the HSM supplier Marvell.
                        cert_object.signature_hash_algorithm)
                    # certificate is validated hence no longer need to be present part of the certificate_list.
                    certificate_list.remove(cert)
                    return cert_object
                except exceptions.InvalidSignature:
                    print(f'Certificate {cert_object.subject} signature verification failed.')
                    # If the issuer and subject matched, the signature verification must succeed.
                    pass
    return None

def verify_attestation_blob(attestation_blob: bytes, cert_object: x509.Certificate, firmware_version: str, verbose: bool = False) -> bool:
    attestation_data: bytes = attestation_blob[:-ATTESTATION_SIGNATURE_SIZE]
    attestation_signature: bytes = attestation_blob[-ATTESTATION_SIGNATURE_SIZE:]
    if firmware_version.startswith("3"):
        return verify_3x_firmware_attestation(attestation_data, attestation_signature, cert_object, verbose)
    elif firmware_version.startswith("2") or firmware_version.startswith("1"):
        return verify_2x_firmware_attestation(attestation_data, attestation_signature, cert_object, verbose)
    else:
            raise ValueError(f"Unsupported firmware version: {firmware_version}")

def verify_3x_firmware_attestation(attestation_data: bytes, attestation_signature: bytes, cert_object: x509.Certificate, verbose: bool = False) -> bool:
        try:
            cert_object.public_key().verify(
                attestation_signature,
                attestation_data,
                padding.PKCS1v15(), # CodeQL [SM04457] The PKCS1v15 padding is used for RSA signature verification as required by the HSM supplier Marvell.
                cert_object.signature_hash_algorithm)
            # The above function does not return anything if the signature is valid. Raises cryptography.exceptions.InvalidSignature – If the signature does not validate.
            return True
        except exceptions.InvalidSignature as e:
            if verbose:
                print(f'Verifying attestation with certificate: "{cert_object.subject}, issuser: {cert_object.issuer}" failed with exception {e}')
            return False

        return False

def verify_2x_firmware_attestation(attestation_blob: bytes, signature: bytes, cert_object: x509.Certificate, verbose: bool = False) -> bool:
    hash_value: bytes = hashlib.sha256(attestation_blob).digest()
    try:
        # Load the certificate
        public_key: rsa.RSAPublicKey = cert_object.public_key()
        
        # Decrypt the signature using the public key
        sig_int: int = int.from_bytes(signature, byteorder='big')
        decrypted_signature: int = pow(sig_int, public_key.public_numbers().e, public_key.public_numbers().n)
        decrypted_signature_bytes: bytes = decrypted_signature.to_bytes((decrypted_signature.bit_length() + 7) // 8, byteorder='big')    

        if decrypted_signature_bytes[-len(hash_value):] == hash_value:
            return True
    except Exception as e:
        if verbose:
            print(f'Verifying attestation with certificate: "{cert_object.subject}, issuser: {cert_object.issuer}" failed with exception {e}')
        return False
    return False

def verify_certs_and_attestation(certificate_bundle_file: str, attestation_file: str, firmware_version: str, verbose: bool = False) -> bool:
    # Load the certificate bundle passed.
    certificate_list: Set[pem.AbstractPEMObject] = set(pem.parse_file(certificate_bundle_file))
    with open(attestation_file, "rb") as f:
        attestation_blob: bytes = f.read()
        return verify_certs_and_attestation_inner(attestation_blob, certificate_list, firmware_version, verbose)

def verify_certificate_chain_and_attestation(attestation_blob: bytes, cert_content: str, firmware_version: str, verbose: bool = False) -> bool:
    certificate_list: Set[pem.AbstractPEMObject] = set(pem.parse(cert_content))
    return verify_certs_and_attestation_inner(attestation_blob, certificate_list, firmware_version, verbose)

def verify_certs_and_attestation_inner(attestation_blob: bytes, certificate_list: Set[pem.AbstractPEMObject], firmware_version: str, verbose: bool = False) -> bool:
    marvell_root_cert_obj: x509.Certificate = x509.load_pem_x509_certificate(MARVELL_HSM_ROOT_CERTIFICATE.encode("utf-8"), backends.default_backend())
    marvell_ls2_root_cert_obj: x509.Certificate = x509.load_pem_x509_certificate(MARVELL_LS2_HSM_ROOT_CERTIFICATE.encode("utf-8"), backends.default_backend())

    # Step 1: Find the intermediate certificate issued by Marvell. The issuer certificate is MARVELL_HSM_ROOT_CERTIFICATE
    if verbose:
        print(f'Verifying certificate chain with Marvell root certificate:')
        pretty_print_certificate(marvell_root_cert_obj)
    marvell_root_issued_certificate = find_issued_certificate(certificate_list, verbose, marvell_root_cert_obj, marvell_ls2_root_cert_obj)
    if not marvell_root_issued_certificate:
        print("Marvell issued certificate not found in the bundle.")
        return False
    if verbose:
        print(colored(f'Found certificate issued by Marvell root certificate:', 'green'))
        pretty_print_certificate(marvell_root_issued_certificate)

    # Step 2: Find the partition certificate issued by marvell intermediate certificate.
    marvell_issued_partition_certificate = find_issued_certificate(certificate_list, verbose, marvell_root_issued_certificate)
    if not marvell_issued_partition_certificate:
        print("Partition certificate not found in the bundle.")
        return False
    
    if verbose:
        print(colored(f'Found partition certificate issued by Marvell intermediate certificate:', 'green'))
        pretty_print_certificate(marvell_issued_partition_certificate)

    # The above assertion establishes the certificate chain.
    # Step 3: Ensure that the partition certificate that chains up to the marvell root certificate validates the key attestation blob.
    print(colored('Certificate chain established with Marvell root certificate', 'green'))
    print('Verifying attestation with certificate issued by HSM Manufacturer (Marvell)')
    verify = verify_attestation_blob(attestation_blob, marvell_issued_partition_certificate, firmware_version, verbose)
    if not verify:
        return False
    print(colored(f'Success!! Attestation blob integrity established with { "below " if verbose else ""}certificate issued by HSM Manufacturer (Marvell)', 'green'))
    if verbose:
        pretty_print_certificate(marvell_issued_partition_certificate)

    print('Verifying certificate chain with partition root certificate...')
    #Step 4: Find partition root level certificate.
    partition_root_cert = get_self_signed_certificate(certificate_list)
    if not partition_root_cert:
        print("Partition root certificate not found in the bundle.")
        return False
    
    if verbose:
        print(colored(f'Partition root certificate:', 'green'))
        pretty_print_certificate(partition_root_cert)

    # Step 5: Find the partition certificate issued by partition root certificate.
    partition_root_issued_certificate = find_issued_certificate(certificate_list, verbose, partition_root_cert)
    if not partition_root_issued_certificate:
        print("Partition root issued intermediate certificate not found in the bundle.")
        return False

    if verbose:
        print(colored(f'Found certificate issued by partition root certificate:', 'green'))
        pretty_print_certificate(partition_root_issued_certificate)
    print(colored(f'Certificate chain established with partition root certificate ', 'green'))
    # Step 6: Ensure that the partition certificate that chains up to the microsoft adapter root certificate validates the key attestation blob.

    print('Verifying attestation with certificate issued by partition root certificate')
    verify = verify_attestation_blob(attestation_blob, partition_root_issued_certificate, firmware_version, verbose)
    if not verify:
        return False

    print(colored(f'Success!! Attestation blob integrity established with {"below " if verbose else ""}partition certificate', 'green'))
    if verbose:
        pretty_print_certificate(partition_root_issued_certificate)

    partition_root_issued_certificate_public_key_bytes: bytes = partition_root_issued_certificate.public_key().public_bytes(
                                                            serialization.Encoding.PEM,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    
    marvell_issued_partition_certificate_public_key_bytes: bytes = marvell_issued_partition_certificate.public_key().public_bytes(
                                                            serialization.Encoding.PEM,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    
    # Step 7. Ensure the public keys of the partition certificates issued by microsoft and marvell match.
    if partition_root_issued_certificate_public_key_bytes != marvell_issued_partition_certificate_public_key_bytes:
        print("Public keys of partition root issued intermediate certificate and Marvell issued certificates do not match.")
        return False


    return True

def get_self_signed_certificate(certificate_list: Set[pem.AbstractPEMObject]) -> Optional[x509.Certificate]:
    for cert in certificate_list:
        cert_utf8_encoded: bytes = cert.as_text().encode("utf-8")
        cert_object: x509.Certificate = x509.load_pem_x509_certificate(cert_utf8_encoded, backends.default_backend())
        if cert_object.subject == cert_object.issuer:
            return cert_object
    return None

def pretty_print_certificate(cert: x509.Certificate) -> None:
    '''
    Print a digital certificate.
    Args:
        cert (x509.Certificate): The digital certificate to print.
    '''
    def sanitize_name(name):
        return name.split(',')[0]

    def print_certificate_subject(subject) -> None:
        subject_cn_attr_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if subject_cn_attr_name:
            print(f'  Abbreviated Common Name (CN): {sanitize_name(subject_cn_attr_name[0].value)}')

        org_name_attr = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if org_name_attr:
            print(f'  Organization Name (O): {sanitize_name(org_name_attr[0].value)}')
        
        org_unit_name_attr = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
        if org_unit_name_attr:
            print(f'  Organizational Unit Name (OU): {sanitize_name(org_unit_name_attr[0].value)}')
        
        country_name_attr = subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
        if country_name_attr:
            print(f'  Country Name (C): {sanitize_name(country_name_attr[0].value)}')
        
        email_attr = subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)
        if email_attr:
            print(f'  Email Address: {sanitize_name(email_attr[0].value)}')

        # Add the following code to print organization identifier and street
        org_identifier_attr = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_IDENTIFIER)
        if org_identifier_attr:
            print(f'  Organization Identifier: {sanitize_name(org_identifier_attr[0].value)}')

        street_attr = subject.get_attributes_for_oid(x509.NameOID.STREET_ADDRESS)
        if street_attr:
            print(f'  Street Address: {sanitize_name(street_attr[0].value)}')

    print('\nSubject:')
    print_certificate_subject(cert.subject)

    # Print certificate issuer
    print('\nIssuer:')
    print_certificate_subject(cert.issuer)

    # Print certificate serial number
    print(f'\nSerial Number: {cert.serial_number}')

    # Print certificate fingerprint (SHA-256)
    print(f'Fingerprint (SHA-256): {cert.fingerprint(hashes.SHA256()).hex()}')
    print('\n')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-cf", "--cert_bundle_file", help="Path to the certificate bundle file.", required=True)
    parser.add_argument("-af", "--attestation_file", help="Path to the attestation file.", required=True)
    parser.add_argument("-v", "--verbose", help="Print verbose logs.", required=False)

    args = parser.parse_args()
    validate_attesation_firmware_version_2x: bool = verify_certs_and_attestation(args.cert_bundle_file, args.attestation_file, '2.x', args.verbose)
    if (validate_attesation_firmware_version_2x or verify_certs_and_attestation(args.cert_bundle_file, args.attestation_file, '3.x', args.verbose)):
        print(colored("Certificate chain and key attestation validation succeeded.", "green"))
        if args.verbose:
            print('\nNote: The common name in the Marvell HSM root certificate includes "Cavium" because Marvell acquired Cavium in 2018.')
            print('You can download and review the Marvell root certificate, which is the same as the one used in this script, from the following link:')  
            print('https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/liquidsecurity-certificate.html')
    else:
        print(colored("Certificate chain and key attestation validation failed.", "red"))
        exit(1)