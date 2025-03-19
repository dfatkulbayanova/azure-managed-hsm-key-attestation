# Azure Managed HSM Key attestation

Key Attestation is a functionality of Azure Managed HSM. It enables a way to validate the integrity and authenticity of
cryptographic keys stored within the hardware security module (HSM). It allows organizations to verify that keys have
been generated and stored within a trusted, FIPS 140-3 Level 3 certified HSM without ever leaving the FIPS boundary.
By providing cryptographic proof that the keys are securely handled, key attestation enhances trust in key management
processes, enabling compliance with stringent security standards and regulations. This feature is especially valuable
in scenarios where customers need assurance that their keys are protected from unauthorized access, even from cloud providers.


## Pre-requisites

1. AZ CLI version: 2.69.0 or higher 

Run `az --version` to find the version. If you need to install or upgrade, see [Install the Azure CLI](/cli/azure/install-azure-cli). 

2. Python version: 3.13.2 or higher 

Run `python3 --version` to find the version. 

3. Pip3 version: 24.3.1 or higher 

Run `pip3 --version` to find the version. 

4. Azure Managed HSM RBAC Permissions: 
Crypto user of the Managed HSM or a custom role with getkey permissions 


## Steps to follow:

### Step 1:
Download or clone the Github repository with all the files required for key attestation

```bash
git clone https://github.com/Azure/azure-managed-hsm-key-attestation
```

### Step 2:

Set up a virtual environment and install the required python packages from requirements.txt.
In this example, we are naming the virtual environment “attestation”.

Note: Make sure you are in  the repository you downloaded or cloned in [step 1](#step-1)
#### Linux Instructions (Ubuntu)

```bash
python3 -m venv attestation
source attestation/bin/activate
pip3 install -r requirements.txt
cd src/
```

#### Windows Instructions

```cmd
python3 –m venv attestation 
attestation\Scripts\activate.bat 
pip3 install –r requirements.txt
cd src/
```

### Step 3:
Get attestation data for a specific key from the HSM using the AZ CLI comand below. Including
key version in the URI is optional. The JSON file contains key properties, attestation blob,
and all certificates required for key attestation. In this example, the json file is named 
attestation.json 

```bash
az rest --method get --uri https://<poolname>.managedhsm.azure.net/keys/<keyname>/<keyversion>/attestation?api-version=7.6-preview.1 --resource https://managedhsm.azure.net > <filename>.json
```

#### Example:

- Download key attestation for a key named `contosokey`
```bash
az rest --method get --uri https://contoso.managedhsm.azure.net/keys/contosokey/attestation?api-version=7.6-preview.1 --resource https://managedhsm.azure.net > attestation.json 
```

- Download key attestation for a key named `contosokey`, specifying key version `48293232e672449b9008602b80618`.

```bash
az rest --method get --uri https://contoso.managedhsm.azure.net/keys/contosokey/48293232e672449b9008602b80618/attestation?api-version=7.6-preview.1 --resource https://managedhsm.azure.net > attestation2.json 
```

### Step 4:
The python script validate_attestation.py extracts the attestation blob and certificates
from the JSON file in the above step. It constructs a certificate chain to confirm that
the key is signed by Marvell, the HSM vendor’s root, and additionally verifies that the
key is signed with a Microsoft-signed certificate. It will also parse the attributes of
the attestation binary and print the results. Symmetric keys will receive both public and
private key attestation, whereas asymmetric keys will receive only private key attestation.
There is an optional parameter of --v or --verbose which can be included to view the
properties of the certificate chain and additional information on the attributes of the key. 

```bash
python3 validate_attestation.py -af <attestation.json>
```

#### Example:

- Without verbose logs:

```bash
python3 validate_attestation.py -af attestation.json
```

- With verbose logs:

```bash
python3 validate_attestation.py -af attestation.json --verbose
```

You can validate all the certificates used in `/src/vendor/marvell/marvell_validate_key_attestation.py`
by checking them against the Marvell website.

- https://www.marvell.com/content/dam/marvell/en/public-collateral/security-solutions/liquid_security_certificate.zip
- https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/liquidsecurity2-certificate-ls2-g-axxx-mi-f-bo-v2.html


## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
