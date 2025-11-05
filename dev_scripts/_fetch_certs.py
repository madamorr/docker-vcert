import json
import requests
import logging
import datetime
import subprocess
import boto3

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


# Get api secret from secrets manager
api_secrets = fetch_aws_secret("pki-tppl-api-key", region_name="us-east-1")
if not api_secrets:
    logger.error("Failed to retrieve API secrets. Exiting.")
    exit(1)

# lambda handler would pass these as parameters in production
api_token = api_secrets["tppl-api-key"]
headers = {"tppl-api-key": f"{api_token}", "accept": "application/json"}
api_base_url = "https://api.venafi.cloud"
minutes = 60
vcert_bin_path = "./vcert_mac"  # Update with actual path to vcert binary
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
                # Here you would add the code to upload the cert to the specified AWS account
                #
                #
                #
                #
                #
    else:
        logger.warning(f"No matching app found for certificate ID {cert_id}. Skipping.")
