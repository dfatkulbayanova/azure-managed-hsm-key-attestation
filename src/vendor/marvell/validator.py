
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

from abc import ABC, abstractmethod
from binascii import hexlify
from .marvell_validate_key_attestation import verify_certificate_chain_and_attestation

class AttestationValidator(ABC):
    @abstractmethod
    def validate_key_attestation(self, attestation_blob, certificates, version, verbose=False):
        pass

class MarvellAttestationValidatorV1(AttestationValidator):
    def validate_key_attestation(self, attestation_blob, certificates, version, verbose=False):
        return verify_certificate_chain_and_attestation(attestation_blob, certificates, "2.", verbose) or verify_certificate_chain_and_attestation(attestation_blob, certificates, "3.", verbose)