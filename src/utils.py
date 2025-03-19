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

import base64, json, argparse
from binascii import hexlify

def get_padded_str(str_content):
    rem = len(str_content) % 4
    str_content += "=" * (4 - rem)
    return str_content

def get_base64_url_decoded(content, byte_mode = False):
    padded_decoded_bytes = base64.urlsafe_b64decode(get_padded_str(content))
    return padded_decoded_bytes if byte_mode else padded_decoded_bytes.decode('utf-8')

def base64_decode_dump_file(file_name_to,file_name_from, byte_mode=False):
    with open(file_name_from, 'r') as file_from:
        with open(file_name_to, 'wb' if byte_mode else 'w') as file:
            padded_decoded_bytes = base64.urlsafe_b64decode(get_padded_str(file_from.read()))
            file.write(padded_decoded_bytes if byte_mode else padded_decoded_bytes.decode('utf-8'))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-ft", "--file_name_to", help="Name of file to write to.", required=True)
    parser.add_argument("-ff", "--file_name_from", help="Name of file to read from.", required=True)  
    parser.add_argument("-byte_mode", "--byte_mode", help="(optional) Write data in byte mode.", required=False)

    args = parser.parse_args()
    base64_decode_dump_file(args.file_name_to, args.file_name_from, args.byte_mode)