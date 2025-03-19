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

#!/usr/bin/python
"""
Script for parsing key attestation files.
"""

import argparse
import binascii
import gzip
import struct
import os
import sys
import json
import csv
from enum import Enum
from rich.console import Console
from rich.table import Table
from tabulate import tabulate

class FirmwareVersion(Enum):
    VERSION_1 = "fw3x"
    VERSION_2 = "fw2x" or "fw10x"
    UNKNOWN = "unknown"

# Constants
VERSION_2_HEADER = '>III'
VERSION_1_RESPONSE_HEADER = '>IIII'
VERSION_1_INFO_HEADER = '>HHHH'
VERSION_1_OBJ_HEADER = '>III'
TLV = '>II'
SIGNATURE_SIZE = 256
CAVIUM_ATTESTATION_OFFSET = 20

ATTRIBUTE_NAMES = {
    0x0100: ("OBJ_ATTR_KEY_TYPE", "Subclass type of the key."),
    0x0162: ("OBJ_ATTR_EXTRACTABLE", "Indicates if key can be extracted."),
    0x0164: ("OBJ_ATTR_NEVER_EXTRACTABLE", "Indicates if key can never be extracted."),
    0x0122: ("OBJ_ATTR_PUBLIC_EXPONENT", "RSA key public exponent value."),
    0x0000: ("OBJ_ATTR_CLASS", "Class type of the key."),
    0x0102: ("OBJ_ATTR_ID", "Key identifier."),
    0x0103: ("OBJ_ATTR_SENSITIVE", "Indicates if the key is sensitive."),
    0x0104: ("OBJ_ATTR_ENCRYPT", "Indicates if key can be used for encryption."),
    0x0105: ("OBJ_ATTR_DECRYPT", "Indicates if key can be used for decryption."),
    0x0106: ("OBJ_ATTR_WRAP", "Indicates if key can be used to wrap other keys."),
    0x0107: ("OBJ_ATTR_UNWRAP", "Indicates if key can be used to unwrap other keys."),
    0x0108: ("OBJ_ATTR_SIGN", "Indicates if key can be used for signing."),
    0x010A: ("OBJ_ATTR_VERIFY", "Indicates if key can be used for verifying."),
    0x010C: ("OBJ_ATTR_DERIVE", "Indicates if key supports key derivation."),
}

NON_VERBOSE_ATTRS = [0x0100, 0x0162, 0x0164, 0x0122, 0x0000, 0x0102]
VERBOSE_ATTRS = NON_VERBOSE_ATTRS + [0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x010A, 0x010C]

# Utility Functions
def interpret_value(attr_type, attr_value):
    if attr_type in [0x0003, 0x0102]:  # OBJ_ATTR_LABEL or OBJ_ATTR_ID
        return binascii.unhexlify(attr_value).decode('utf-8').strip('\x00')
    elif attr_type == 0x0100:  # OBJ_ATTR_KEY_TYPE
        key_type_mapping = {
            b'00': "CKK_RSA",
            b'01': "CKK_DSA",
            b'02': "CKK_DH",
            b'03': "CKK_EC",
            b'04': "CKK_X9_42_DH",
            b'05': "CKK_KEA",
            b'10': "CKK_GENERIC_SECRET",
            b'11': "CKK_RC2",
            b'12': "CKK_RC4",
            b'13': "CKK_DES",
            b'14': "CKK_DES2",
            b'15': "CKK_DES3",
            b'16': "CKK_CAST",
            b'17': "CKK_CAST3",
            b'18': "CKK_CAST128",
            b'19': "CKK_RC5",
            b'1a': "CKK_IDEA",
            b'1b': "CKK_SKIPJACK",
            b'1c': "CKK_BATON",
            b'1d': "CKK_JUNIPER",
            b'1e': "CKK_CDMF",
            b'1f': "CKK_AES",
            b'20': "CKK_BLOWFISH",
            b'21': "CKK_TWOFISH",
            b'22': "CKK_SECURID",
            b'23': "CKK_HOTP",
            b'24': "CKK_ACTI",
            b'25': "CKK_CAMELLIA",
            b'26': "CKK_ARIA",
            b'27': "CKK_SHA512_224_HMAC",
            b'28': "CKK_SHA512_256_HMAC",
            b'29': "CKK_SHA512_T_HMAC",
            b'80000000': "CKK_VENDOR_DEFINED",
        }
        return key_type_mapping.get(attr_value.encode('utf-8'), "Unknown Key Type")
    elif attr_type == 0x0122:  # OBJ_ATTR_PUBLIC_EXPONENT
        return str(int(attr_value, 16))
    elif attr_type == 0x0161:  # OBJ_ATTR_VALUE_LEN
        return str(int(attr_value, 16)) + " bytes"
    elif attr_type == 0x0000:  # OBJ_ATTR_CLASS
        class_type_mapping = {
            b'00': "CKO_DATA",             
            b'01': "CKO_CERTIFICATE",      
            b'02': "CKO_PUBLIC_KEY",       
            b'03': "CKO_PRIVATE_KEY",      
            b'04': "CKO_SECRET_KEY",       
            b'05': "CKO_HW_FEATURE",       
            b'06': "CKO_DOMAIN_PARAMETERS",
            b'07': "CKO_MECHANISM",        
            b'08': "CKO_OTP_KEY",          
        }
        return class_type_mapping.get(attr_value.encode('utf-8'), "Unknown Class Type")
    elif attr_type in [0x0162, 0x0164]:
        return "CK_TRUE" if attr_value == '01' else "CK_FALSE"
    return attr_value

def get_contents(attestation_file):
    with open(attestation_file, 'rb') as f:
        return f.read()

def parse_attributes(attestation, header_format):
    """Parse attributes from the attestation."""
    _, attr_count, _ = struct.unpack_from(header_format, attestation, 0)
    obj_header_size = struct.calcsize(header_format)
    attestation = attestation[obj_header_size:]
    attributes = {}

    for _ in range(attr_count):
        attr_type, attr_len = struct.unpack_from(TLV, attestation, 0)
        attestation = attestation[struct.calcsize(TLV):]
        attr_value = binascii.hexlify(attestation[:attr_len]).decode('utf-8')
        attributes[attr_type] = attr_value
        attestation = attestation[attr_len:]

    return attributes

def parse_headers(attestation):
    _, _, totalsize, bufsize = struct.unpack_from(VERSION_1_RESPONSE_HEADER, attestation, 0)
    attribute_offset = totalsize - (bufsize + SIGNATURE_SIZE)
    attest_data = attestation[attribute_offset:]
    _, _, offset1, offset2 = struct.unpack_from(VERSION_1_INFO_HEADER, attest_data, 0)
    return attest_data, offset1, offset2

def parse_version_1(attest_data):
    return parse_attributes(attest_data, VERSION_1_OBJ_HEADER)

def detect_version(attestation):
    """Detect the firmware version."""
    try:
        parse_attributes(attestation, VERSION_2_HEADER)
        return FirmwareVersion.VERSION_2
    except Exception:
        return FirmwareVersion.VERSION_1

def extract_key_details(attr_value):
    """Extract key name and ID from attribute value."""
    parts = attr_value.split('/')
    return parts[-2], parts[-1]

def print_attributes(attributes, verbose=False, pretty=False, output="table"):
    """Print attributes in the desired format."""
    attributes_interpreted = {}
    attr_list = VERBOSE_ATTRS if verbose else NON_VERBOSE_ATTRS
    rows = []
    interpreted_value = interpret_value(0x0102, attributes[0x0102])

    for attr_type in attr_list: 
        if attr_type in attributes:
            attr_name, description = ATTRIBUTE_NAMES.get(attr_type, ("Undocumented", ""))

            interpreted_value = interpret_value(attr_type, attributes[attr_type])

            attributes_interpreted[attr_name] = interpreted_value
            rows.append([attr_name, interpreted_value, description])

    key_name, key_id = extract_key_details(interpret_value(0x0102, attributes[0x0102]))
    header_text = f"Attested key attributes for Key '{key_name}' with version '{key_id}'"

    if pretty:
        console = Console()
        table = Table(title=header_text, title_style="bold green")
        table.add_column("Attribute", style="cyan bold")
        table.add_column("Interpreted Value", style="green bold")
        table.add_column("Description", style="magenta bold")
        for row in rows:
            table.add_row(*row)
        console.print(table)
    elif output == "json":
        json_output = {
            "header": header_text,
            "attributes": [
                {"Attribute": row[0], "Interpreted Value": row[1], "Description": row[2]}
                for row in rows
            ],
        }
        with open("output.json", "w") as f:
            json.dump(json_output, f, indent=4)
            print(f"Output written to output.json")

    elif output == "csv":
        with open("output.csv", mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([header_text])
            writer.writerow(["Attribute", "Interpreted Value", "Description"])
            writer.writerows(rows)
            print(f"Output written to output.csv")
    else:
        print(header_text)
        print(tabulate(rows, headers=["Attribute", "Interpreted Value", "Description"], tablefmt="grid"))

    return attributes_interpreted

def parse_attestation(attestation_blob, verbose, pretty, output = "table"):
    version = detect_version(attestation_blob)

    if version == FirmwareVersion.VERSION_2:
        attributes = parse_attributes(attestation_blob[CAVIUM_ATTESTATION_OFFSET:], VERSION_2_HEADER)
    elif version == FirmwareVersion.VERSION_1:
        attest_data, offset1, offset2 = parse_headers(attestation_blob)
        attributes = parse_version_1(attest_data[offset1:])
    else:
        raise ValueError("Unsupported firmware version")

    attr_dict = print_attributes(attributes, verbose, pretty, output)
    return attr_dict

def main(args=None):
    parser = argparse.ArgumentParser(description="Parse key attestation files.")
    parser.add_argument("--attestation_file", required=True, help="Path to the attestation file.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--pretty", action="store_true", help="Enable pretty output.")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table", help="Output format.")
    args = parser.parse_args()

    try:
        attestation = get_contents(args.attestation_file)
        return parse_attestation(attestation, verbose=args.verbose, pretty=args.pretty, output=args.output)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()