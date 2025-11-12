import json
import requests
import logging
import datetime
import subprocess
import boto3
import re, hashlib, base64
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key, NoEncryption, PrivateFormat
from cryptography.hazmat.backends import default_backend
from cryptography import x509

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


def fetch_aws_secret(secret_name, region_name="us-east-1"):
    logger.info(
        f"Fetching secret '{secret_name}' from AWS Secrets Manager in region '{region_name}'"
    )
    try:
        client = boto3.client("secretsmanager", region_name=region_name)
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret_string = get_secret_value_response.get("SecretString")
        if not secret_string:
            logger.error(f"Secret '{secret_name}' has no SecretString value.")
            return None
        try:
            secret_dict = json.loads(secret_string)
            logger.info(
                f"Successfully fetched and parsed secret '{secret_name}'. Keys: {list(secret_dict.keys())}"
            )
            return secret_dict
            
        except json.JSONDecodeError as e:
            logger.error(f"Secret '{secret_name}' is not valid JSON: {e}")
            return None
    except client.exceptions.ResourceNotFoundException:
        logger.error(f"Secret '{secret_name}' not found in region '{region_name}'.")
    except client.exceptions.DecryptionFailure:
        logger.error(f"Decryption failure for secret '{secret_name}'.")
    except client.exceptions.InvalidRequestException as e:
        logger.error(f"Invalid request for secret '{secret_name}': {e}")
    except client.exceptions.InvalidParameterException as e:
        logger.error(f"Invalid parameter for secret '{secret_name}': {e}")
    except Exception as e:
        logger.error(f"Unexpected error fetching secret '{secret_name}': {e}")
    return None


def fetch_aws_applications_data(api_base_url, headers):
    """Fetch all applications and filter those starting with 'aws_'"""
    try:
        app_url = f"{api_base_url}/outagedetection/v1/applications"
        logger.info(f"Requesting applications from {app_url}")
        response = requests.get(app_url, headers=headers)
        response.raise_for_status()
        applications = response.json().get("applications", [])
        logger.info(f"Fetched {len(applications)} applications from API.")
    except requests.RequestException as e:
        logger.error(f"Failed to fetch applications: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error fetching applications: {e}")
        return []

    app_name_id_list = [
        {"app": app["name"], "id": app["id"]}
        for app in applications
        if app["name"].startswith("aws_")
    ]
    logger.info(f"Found {len(app_name_id_list)} applications starting with 'aws_'")
    return app_name_id_list


def fetch_certificates_data(api_base_url, headers, minutes):
    """Fetch all certificates issued in the last 'minutes' minutes."""
    now = datetime.datetime.now(datetime.timezone.utc)
    validityStart = now - datetime.timedelta(minutes=minutes)
    validityStart_ISO = validityStart.strftime("%Y-%m-%dT%H:%M")
    logger.info(f"Fetching certificates with validity start after {validityStart_ISO}")

    all_certificates = []
    page_number = 0
    page_size = 100

    while True:
        payload = {
            "ordering": {"orders": [{"direction": "DESC", "field": "validityStart"}]},
            "paging": {"pageNumber": page_number, "pageSize": page_size},
            "expression": {
                "operator": "AND",
                "operands": [
                    {
                        "field": "validityStart",
                        "operator": "GTE",
                        "value": validityStart_ISO,
                    },
                    {"field": "certificateStatus", "operator": "EQ", "value": "ACTIVE"},
                    {"field": "versionType", "operator": "EQ", "value": "CURRENT"},
                ],
            },
        }

        search_url = f"{api_base_url}/outagedetection/v1/certificatesearch?ownershipTree=false&excludeSupersededInstances=true"
        logger.info(
            f"Retrieving certificate data.. page: {page_number} size: {page_size} from {search_url} with payload: {payload}"
        )
        try:
            response = requests.post(search_url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            certificates = data.get("certificates", [])
            all_certificates.extend(certificates)
            paging = data.get("paging", {})
            total_pages = paging.get("totalPages")
            if total_pages is not None and page_number + 1 >= total_pages:
                break
            if not certificates:
                break
            page_number += 1
        except requests.RequestException as e:
            logger.error(f"Failed to fetch certificates: {e}")
            return all_certificates
        except Exception as e:
            logger.error(f"Unexpected error fetching certificates: {e}")
            return all_certificates

    logger.info(
        f"Data retrieved for {len(all_certificates)} certificates from API (page {page_number})."
    )
    return all_certificates


def fetch_cert_key_chain(api_token, token_switch, vcert_bin_path, cert_request_id):
    logger.info(f"Fetching cert pem for certificate request ID: {cert_request_id}")
    logger.info(
        f"Returning in the order of leaf_cert, issuing_cert, root_cert, private_key"
    )
    try:
        fetch_cert_chain = subprocess.run(
            [
                vcert_bin_path,
                "pickup",
                "-p",
                "vcp",
                token_switch,
                api_token,
                "--pickup-id",
                cert_request_id,
                "--format",
                "json",
                "--no-prompt",
                "--timeout",
                "60",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        json_data = json.loads(fetch_cert_chain.stdout)
        private_key = json_data["PrivateKey"]
        leaf_cert = json_data["Certificate"]
        root_cert = json_data["Chain"][-1]
        issuing_cert = json_data["Chain"][0]
        return leaf_cert, issuing_cert, root_cert, private_key
    except subprocess.CalledProcessError as e:
        logger.error(f"vcert failed: {e}")
        logger.error(f"stderr: {e.stderr}")
    except Exception as e:
        logger.error(f"Error fetching or parsing cert: {e}")
    return None, None, None, None

def format_pem_oneline_to_multiline(oneline_pem_string, line_length=64):
    """
    Formats a one-line PEM string into a multi-line, properly formatted PEM block.

    Args:
        oneline_pem_string (str): The single-line PEM string.
        line_length (int): The desired line length for the base64 encoded data.
                           Default is 64 characters.

    Returns:
        str: The multi-line, properly formatted PEM string.
    """
    # Extract the header, footer, and the base64 encoded data
    parts = oneline_pem_string.split("-----")
    header = f"-----{parts[1]}-----"
    footer = f"-----{parts[3]}-----"
    encoded_data = parts[2].strip()

    # Format the base64 encoded data into multiple lines
    formatted_data_lines = []
    for i in range(0, len(encoded_data), line_length):
        formatted_data_lines.append(encoded_data[i : i + line_length])

    # Join the parts to form the multi-line PEM string
    multiline_pem_string = "\n".join([header] + formatted_data_lines + [footer])
    return multiline_pem_string

def normalize_pem(value: str) -> bytes:
    # remove accidental surrounding quotes
    v = value.strip().strip("'").strip('"')
    # turn literal "\n" into real newlines; normalize line endings
    v = v.replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
    # ensure it ends with a newline (some parsers are picky)
    if not v.endswith("\n"):
        v += "\n"
    return v.encode("utf-8")

def decrypt_private_key(encrypted_pem: str, password: str) -> str:
    """
    Decrypt an encrypted private key and return it as an unencrypted PEM string.
    If the key is already unencrypted, return it as-is.
    
    Args:
        encrypted_pem (str): The encrypted private key in PEM format
        password (str): The password to decrypt the key
        
    Returns:
        str: The unencrypted private key in PEM format
    """
    try:
        # First, try to load it as an unencrypted key
        try:
            private_key_obj = load_pem_private_key(
                encrypted_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            logger.info("Private key is already unencrypted")
            return encrypted_pem
        except TypeError:
            # If we get TypeError, it means the key needs a password
            pass
        
        # Try to decrypt with the provided password
        private_key_obj = load_pem_private_key(
            encrypted_pem.encode('utf-8'),
            password=password.encode('utf-8'),
            backend=default_backend()
        )
        # Serialize it back to PEM without encryption
        unencrypted_pem = private_key_obj.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
        logger.info("Private key decrypted successfully")
        return unencrypted_pem.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to decrypt private key: {e}")
        return encrypted_pem  # Return original if decryption fails

PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\r?\n.*?\r?\n-----END CERTIFICATE-----",
    re.DOTALL,
)

def describe_pem(label, pem_text: str):
    blocks = PEM_CERT_RE.findall(pem_text or "")
    print(f"{label}: {len(blocks)} certificate block(s)")
    for i, b in enumerate(blocks, 1):
        print(f"  [{i}] length={len(b)} bytes")

def sha256_der(pem:str)->str:
    # compute sha256 of DER to positively identify the cert body
    b64 = "".join(line for line in pem.splitlines() if line and "CERTIFICATE" not in line and "-" not in line)
    der = __import__("base64").b64decode(b64)
    return hashlib.sha256(der).hexdigest()

def debug_param(label, s: str):
    print(f"\n== {label} ==")
    print("len:", len(s))
    print("BEGIN count:", s.count("BEGIN CERTIFICATE"))
    print("END count:", s.count("END CERTIFICATE"))
    blocks = PEM_CERT_RE.findall(s or "")
    print("regex blocks:", len(blocks))
    if blocks:
        print("first block sha256:", sha256_der(blocks[0])[:16])
   
def only_first_block(pem_text:str)->str:
    m = PEM_CERT_RE.search(pem_text or "")
    if not m:
        raise ValueError("No CERTIFICATE block found in Certificate param at call-time.")
    block = m.group(0)
    return block if block.endswith("\n") else block + "\n"

def split_blocks(pem_text:str):
    return PEM_CERT_RE.findall(pem_text or "") 
    
if __name__ == "__main__":
    # Get api secret from secrets manager
    api_secrets = fetch_aws_secret("pki-tppl-api-key", region_name="us-east-1")
    if not api_secrets:
        logger.error("Failed to retrieve API secrets. Exiting.")
        exit(1)

    # lambda handler would pass these as parameters in production
    api_token = api_secrets["tppl-api-key"]
    headers = {"tppl-api-key": f"{api_token}", "accept": "application/json"}
    api_base_url = "https://api.venafi.cloud"
    minutes = 6000
    vcert_bin_path = "D:\\git\\docker-vcert\\dev_scripts\\vcert_win.exe"  # Update with actual path to vcert binary
    token_switch = "-k"
    ######

    # fetch data
    apps_list = fetch_aws_applications_data(api_base_url, headers)
    certs_list = fetch_certificates_data(api_base_url, headers, minutes)

    # Process each certificate
    # download certs
    # upload to aws accounts
    for cert in certs_list:
        cert_id = cert["id"]
        logger.info(f"Processing certificate ID: {cert_id}")
        logger.info(f"Certificate Request ID: {cert['certificateRequestId']}")
        logger.info(f"With Subject CN: {cert['subjectCN']}")
        logger.info(f"With Serial Number: {cert['serialNumber']}")
        # Get application IDs associated with the certificate
        cert_app_ids = cert["applicationIds"]

        # Check if cert is associated with any of the target aws applications
        app_found = False
        for appId in cert_app_ids:
            if any(appId == app["id"] for app in apps_list):
                app_found = True
                break

        if app_found:
            logger.info(f"Found matching app(s) for certificate ID {cert_id}")

            logger.info(
                f"Downloading certificate key and chain for certificate ID {cert_id}"
            )
            leaf_cert, issuing_cert, root_cert, private_key = fetch_cert_key_chain(
                api_token, token_switch, vcert_bin_path, cert["certificateRequestId"]
            )

            if not leaf_cert or not issuing_cert or not root_cert:
                logger.error(
                    f"Failed to retrieve Leaf, issuing, root certificate for certificate ID {cert_id}. No need to process this cert, skipping."
                )
                continue

            if not private_key:
                logger.warning(
                    f"Private key was not present for certificate ID {cert_id}. no need to process this cert, skipping."
                )
                continue

            # Logging cert details to demonstrate retrieval
            logger.info(f"private_key: {private_key}")
            logger.info(f"leaf_cert: {leaf_cert}")
            logger.info(f"issuing_cert: {issuing_cert}")
            logger.info(f"root_cert: {root_cert}")
            # Build chain PEM
            chain_pem = issuing_cert + root_cert
            for app_id in cert_app_ids:
                app_name = next(
                    (app_item["app"] for app_item in apps_list if app_item["id"] == app_id),
                    None,
                )
                if app_name:
                    aws_account_number = app_name.split("_")[2]
                    logger.info(
                        f"Cert will need to be uploaded to AWS Account Number {aws_account_number} for app {app_name}"
                    )
                    logger.info(
                        f"Here you would add the code to upload the cert to the specified AWS account {aws_account_number}"
                    )
                    # First, let's put them into certificate manager.
                    acm = boto3.client("acm", region_name="us-east-1")
                    # Set the existing ARN to None since we are adding a new certificate.
                    existing_arn = None
                    
                    describe_pem("Certificate param", leaf_cert)
                    debug_param("Certificate", leaf_cert)
                    
                    # Recompute NOW (no trust in earlier variables)
                    leaf_block = only_first_block(leaf_cert)
                    
                    # Double-check: count certificates in leaf_block
                    cert_count = leaf_block.count("BEGIN CERTIFICATE")
                    logger.info(f"Certificate block has {cert_count} certificate(s)")
                    
                    if cert_count != 1:
                        logger.error(f"ERROR: Expected 1 certificate, got {cert_count}. This will cause AWS ACM to reject it.")
                    
                    chain_blocks = [b for b in split_blocks(chain_pem or "")]

                    # Drop any duplicate of the leaf from chain, just in case
                    chain_blocks = [b for b in chain_blocks if b != leaf_block]
                    chain_final = "".join(b if b.endswith("\n") else b+"\n" for b in chain_blocks) or None

                    print("Chain blocks:", len(chain_blocks), "total len:", len(chain_final or ""))
                    
                    # Use the leaf block directly - don't re-process it
                    # AWS ACM expects PEM format as STRING, not bytes
                    leaf_cert_str = leaf_block if isinstance(leaf_block, str) else leaf_block.decode('utf-8')
                    private_key_str = private_key if isinstance(private_key, str) else private_key.decode('utf-8')
                    chain_final_str = chain_final if isinstance(chain_final, str) else chain_final.decode('utf-8') if chain_final else None
                    
                    # Debug: print what we're about to send
                    logger.info(f"Certificate to send - length: {len(leaf_cert_str)}, starts with: {leaf_cert_str[:50]}")
                    logger.info(f"Certificate ends with: {leaf_cert_str[-50:]}")
                    logger.info(f"Private key - length: {len(private_key_str)}")
                    logger.info(f"Private key first 50 chars: {private_key_str[:50]}")
                    logger.info(f"Private key last 50 chars: {private_key_str[-50:]}")
                    
                    logger.info(f"About to call import_certificate with:")
                    logger.info(f"  Certificate length: {len(leaf_cert_str)}")
                    logger.info(f"  PrivateKey length: {len(private_key_str)}")
                    logger.info(f"  CertificateChain length: {len(chain_final_str) if chain_final_str else 0}")
                    
                    # Try to convert the private key to PKCS#8 format (which AWS ACM prefers)
                    # NOTE: vcert appears to output PKCS#8 format data but with "BEGIN RSA PRIVATE KEY" header
                    # We need to fix this mismatch
                    logger.info("Fixing private key PEM header if necessary...")
                    if private_key_str.startswith("-----BEGIN RSA PRIVATE KEY-----"):
                        logger.info("Detected RSA PRIVATE KEY header on likely PKCS#8 content")
                        # Try to load as PKCS#8 despite wrong header
                        try:
                            # Replace header temporarily to load correctly
                            pkcs8_key_str = private_key_str.replace(
                                "-----BEGIN RSA PRIVATE KEY-----",
                                "-----BEGIN PRIVATE KEY-----"
                            ).replace(
                                "-----END RSA PRIVATE KEY-----",
                                "-----END PRIVATE KEY-----"
                            )
                            key_obj = load_pem_private_key(
                                pkcs8_key_str.encode('utf-8'),
                                password=None,
                                backend=default_backend()
                            )
                            logger.info("Successfully loaded key with corrected header!")
                            # Re-export as proper PKCS#8
                            private_key_str = key_obj.private_bytes(
                                encoding=Encoding.PEM,
                                format=PrivateFormat.PKCS8,
                                encryption_algorithm=NoEncryption()
                            ).decode('utf-8')
                            private_key_str = pkcs8_key_str
                            logger.info("Converted to proper PKCS#8 format with correct header")
                        except Exception as e:
                            logger.warning(f"Failed to fix header: {e}")
                    else:
                        # Try original loading
                        try:
                            key_obj = load_pem_private_key(
                                private_key_str.encode('utf-8'),
                                password=None,
                                backend=default_backend()
                            )
                            logger.info("Successfully loaded key in original format")
                        except Exception as e:
                            logger.warning(f"Could not parse private key: {e}")
                            logger.warning("Attempting to send key in original format...")
                    
                    logger.info(f"Final state before import:")
                    logger.info(f"  Certificate length: {len(leaf_cert_str)}")
                    logger.info(f"  PrivateKey length: {len(private_key_str)}")
                    logger.info(f"  PrivateKey header: {private_key_str[:40]}")
                    logger.info(f"  PrivateKey footer: {private_key_str[-40:]}")
                    
                    resp = acm.import_certificate(
                        Certificate=leaf_cert_str,
                        PrivateKey=private_key_str,
                        CertificateChain=chain_final_str,
                        #CertificateArn=existing_arn,  # keep None to create a brand new cert
                        Tags=[{"Key": "AWSImport1", "Value": "TLSPC-BOFA"}]
                    )
                    
                    if resp:
                        cert_arn = resp.get('CertificateArn', 'Unknown ARN')
                        logger.info(f"✓ Certificate successfully imported to AWS ACM!")
                        logger.info(f"  Certificate ARN: {cert_arn}")
                        logger.info(f"  Certificate ID: {resp.get('CertificateId', 'Unknown')}")
                   
                    
        else:
            logger.warning(f"No matching app found for certificate ID {cert_id}. Skipping.")


    logger.info("=" * 80)
    logger.info("Certificate import process completed successfully!")
    logger.info("=" * 80)

