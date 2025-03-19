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
import os
import argparse
import sys
import json
from termcolor import colored
import utils
import config
from validator import validate_key_attestation
from parser import parse_key_attestation

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-af", "--attestation-file", help="Path to the attestation file.", required=True)
    parser.add_argument("-v", "--verbose", help="Print verbose logs.", action="store_true")

    args = parser.parse_args()
    if not os.path.exists(args.attestation_file):
        print(colored(f"Failed: Given file with name: {args.attestation_file} is not found.", 'red'))
        sys.exit(1)

    key_attestation_properties = {}
    try:
        with open(args.attestation_file, 'r') as file:
            attestation_json_content = json.load(file)

        # Check if the customer has passed the entire attestation output or just the attributes and attestation fields.
        if config.ATTRIBUTES in attestation_json_content:
            attestation_json_content = attestation_json_content[config.ATTRIBUTES]
        if config.ATTESTATION in attestation_json_content:
            attestation_json_content = attestation_json_content[config.ATTESTATION]

        for prop in config.REQUIRED_PROPERTIES:
            if prop not in attestation_json_content:
                print(colored(f"Missing required property '{prop}' in the attestation file.", "red"))
                exit(1)
            key_attestation_properties[prop] = attestation_json_content[prop]

        # Check if the attestation file contains the public key attestation property. This property will only be present
        # in the attestation file if the attestation is for a public key.
        if config.PUBLIC_KEY_ATTESTATION in attestation_json_content:
            key_attestation_properties[config.PUBLIC_KEY_ATTESTATION] = attestation_json_content[config.PUBLIC_KEY_ATTESTATION]

    except json.JSONDecodeError as e:
        print(colored(f"Failed: {args.attestation_file} is not a valid JSON file.", 'red'))
        sys.exit(1)

    version = key_attestation_properties[config.VERSION]
    certificates = utils.get_base64_url_decoded(key_attestation_properties[config.CERTIFICATE_PEM_FILE])
    
    private_key_attestation_blob = utils.get_base64_url_decoded(key_attestation_properties[config.PRIVATE_KEY_ATTESTATION], byte_mode = True)

    print('Validating private key attestation...')
    if validate_key_attestation(private_key_attestation_blob, certificates, version, args.verbose):
        print(colored("Private key attestation is valid.\n", 'green'))

        # Once the private key attestation is validated, parse the attestation to get the key attributes.
        parse_key_attestation(private_key_attestation_blob, version, args.verbose)

    else:
        print(colored("Private key attestation is invalid.\n", 'red'))
        sys.exit(1)

    if config.PUBLIC_KEY_ATTESTATION in key_attestation_properties:
        print('Validating public key attestation...')
        public_key_attestation_blob = utils.get_base64_url_decoded(key_attestation_properties[config.PUBLIC_KEY_ATTESTATION], byte_mode = True)
        if validate_key_attestation(public_key_attestation_blob, certificates, version, args.verbose):
            print(colored("Public key attestation is valid.\n", 'green'))

            # Once the public key attestation is validated, parse the attestation to get the key attributes.
            parse_key_attestation(public_key_attestation_blob, version, args.verbose)

        else:
            print(colored("Public key attestation is invalid.\n", 'red'))
            sys.exit(1)