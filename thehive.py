import logging
import json
import os
import requests
import argparse
import re
import base64
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from dotenv import load_dotenv
import sys

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("virustotal_cases.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

load_dotenv()
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "mCKulcObLAPTzsP6bxDi5Evbn78tBk7t")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "6cacd21b6231f4304e2d8c87e877513f3523e5f0b4d594681a448fa71ca04053")
ORGANISATION = os.getenv("THEHIVE_ORGANISATION", "Ynov_Corp")

def is_public_ip(ip):
    try:
        ip_addr = ipaddress.ip_address(ip)
        is_public = not (ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_reserved)
        logger.debug(f"IP {ip} is {'public' if is_public else 'private'}")
        return is_public
    except ValueError:
        logger.warning(f"Invalid IP address: {ip}")
        return False

def validate_input(input_value):
    try:
        ipaddress.ip_address(input_value)
        logger.debug(f"Input {input_value} validated as IP")
        return "ip"
    except ValueError:
        pass

    url_pattern = re.compile(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$')
    if url_pattern.match(input_value):
        logger.debug(f"Input {input_value} validated as URL")
        return "url"

    hash_pattern = re.compile(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')
    if hash_pattern.match(input_value):
        logger.debug(f"Input {input_value} validated as hash")
        return "hash"

    logger.error(f"Invalid input: {input_value} (not an IP, URL, or hash)")
    raise ValueError(f"Invalid input: {input_value}")

def parse_openvas(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        findings = []
        for result in root.findall(".//result"):
            ip = result.findtext("host") or "N/A"
            name = result.findtext("name") or "Unknown"
            severity = result.findtext("severity") or "0.0"
            description = result.findtext("description") or "No description"
            nvt_oid = result.find("nvt").get("oid") if result.find("nvt") is not None else "N/A"
            try:
                severity_float = float(severity)
                logger.debug(f"Parsed severity as float: {severity_float} for finding: {name}")
            except ValueError:
                logger.error(f"Invalid severity value: {severity} for finding: {name}")
                severity_float = 0.0
            findings.append({
                'ip': ip,
                'name': name,
                'severity': severity_float,
                'description': description,
                'nvt_oid': nvt_oid
            })
        logger.info(f"✓ Parsed {len(findings)} findings from XML")
        return findings
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in parse_openvas: {e}")
        raise

def query_virustotal(input_value, input_type):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        if input_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{input_value}"
        elif input_type == "url":
            encoded_url = base64.urlsafe_b64encode(input_value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        else:
            url = f"https://www.virustotal.com/api/v3/files/{input_value}"

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        vt_data = response.json()
        logger.info(f"✓ Enriched {input_type} {input_value} with VirusTotal")
        return vt_data
    except requests.RequestException as e:
        logger.error(f"Failed to query VirusTotal for {input_type} {input_value}: {e}")
        return {}

def is_suspicious_vt(vt_data, input_type):
    if not vt_data or 'data' not in vt_data or 'attributes' not in vt_data['data']:
        logger.debug("No valid VirusTotal data")
        return False
    stats = vt_data['data']['attributes'].get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    reputation = vt_data['data']['attributes'].get('reputation', 0) if input_type == "ip" else 0
    is_suspicious = malicious > 0 or reputation < 0
    logger.debug(f"VirusTotal stats: {stats}, reputation: {reputation}, suspicious: {is_suspicious}")
    return is_suspicious

def create_openvas_case(finding, vt_data=None):
    try:
        ip = finding['ip']
        title = f"Vulnerability: {finding['name']} on {ip}"
        case_data = {
            "title": title,
            "description": f"""
**Vulnerability**: {finding['name']}
**IP**: {ip}
**Severity**: {finding['severity']}
**Description**: {finding['description']}
**NVT OID**: {finding['nvt_oid']}
{f"**VirusTotal Results**: {json.dumps(vt_data, indent=2)}" if vt_data else ""}
            """,
            "severity": min(int(finding['severity'] * 3 / 10) + 1, 3),
            "tlp": 2,
            "status": "New",
            "tags": ["OpenVAS", f"severity:{finding['severity']}", "vulnerability"],
            "startDate": int(datetime.now().timestamp() * 1000)
        }
        headers = {
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json",
            "X-Organisation": ORGANISATION
        }
        logger.debug(f"Creating case with data: {json.dumps(case_data, indent=2)}")
        response = requests.post(f"{THEHIVE_URL}/api/v1/case", json=case_data, headers=headers, timeout=10)
        response.raise_for_status()
        logger.debug(f"Case creation response: {response.json()}")
        case_id = response.json().get('_id')
        if not case_id:
            raise ValueError("No '_id' in response")

        if ip != "N/A":
            observable_data = {
                "dataType": "ip",
                "data": ip,
                "tlp": 2,
                "tags": ["OpenVAS", "VirusTotal" if vt_data else "OpenVAS"],
                "message": f"Target IP{' with VirusTotal enrichment' if vt_data else ''}"
            }
            obs_response = requests.post(
                f"{THEHIVE_URL}/api/v1/case/{case_id}/observable",
                json=observable_data,
                headers=headers,
                timeout=10
            )
            obs_response.raise_for_status()
            logger.info(f"✓ Observable added for IP {ip} to case {case_id}")

        logger.info(f"✓ Case created with ID: {case_id}")
        return case_id
    except requests.RequestException as e:
        logger.error(f"Failed to create case: {e}, Response: {response.text if 'response' in locals() else 'No response'}")
        return None
    except Exception as e:
        logger.error(f"Failed to create case: {e}")
        return None

def create_vt_case(input_value, input_type, vt_data):
    try:
        title = f"Suspicious {input_type.capitalize()} Analysis: {input_value}"
        case_data = {
            "title": title,
            "description": f"""
**{input_type.capitalize()}**: {input_value}
**VirusTotal Results**: {json.dumps(vt_data, indent=2)}
            """,
            "severity": 2,
            "tlp": 2,
            "status": "New",
            "tags": ["VirusTotal", input_type, "suspicious"],
            "startDate": int(datetime.now().timestamp() * 1000)
        }
        headers = {
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json",
            "X-Organisation": ORGANISATION
        }
        logger.debug(f"Creating case with data: {json.dumps(case_data, indent=2)}")
        response = requests.post(f"{THEHIVE_URL}/api/v1/case", json=case_data, headers=headers, timeout=10)
        response.raise_for_status()
        logger.debug(f"Case creation response: {response.json()}")
        case_id = response.json().get('_id')
        if not case_id:
            raise ValueError("No '_id' in response")

        observable_data = {
            "dataType": input_type,
            "data": input_value,
            "tlp": 2,
            "tags": ["VirusTotal", input_type],
            "message": f"Analyzed {input_type.capitalize()}"
        }
        obs_response = requests.post(
            f"{THEHIVE_URL}/api/v1/case/{case_id}/observable",
            json=observable_data,
            headers=headers,
            timeout=10
        )
        obs_response.raise_for_status()
        logger.info(f"✓ Observable added for {input_type} {input_value} to case {case_id}")

        logger.info(f"✓ Case created with ID: {case_id}")
        return case_id
    except requests.RequestException as e:
        logger.error(f"Failed to create case: {e}, Response: {response.text if 'response' in locals() else 'No response'}")
        return None
    except Exception as e:
        logger.error(f"Failed to create case: {e}")
        return None

def save_openvas_results(findings, cases):
    try:
        os.makedirs("scan_results", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join("scan_results", f"scan_results_{timestamp}.json")
        output_data = {
            "findings": [
                {
                    "ip": f["ip"],
                    "name": f["name"],
                    "severity": f["severity"],
                    "description": f["description"],
                    "nvt_oid": f["nvt_oid"],
                    "case_id": next((c["case_id"] for c in cases if c["finding"] is f), None)
                } for f in findings
            ],
            "cases_created": cases
        }
        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)
        logger.info(f"✓ Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        raise

def save_vt_results(input_value, input_type, vt_data, case_id):
    try:
        os.makedirs("scan_results", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join("scan_results", f"scan_results_{timestamp}.json")
        output_data = {
            "input": {
                "type": input_type,
                "value": input_value
            },
            "virustotal_results": vt_data,
            "case_id": case_id
        }
        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)
        logger.info(f"✓ Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Process OpenVAS XML or query VirusTotal for IP/URL/hash.")
    parser.add_argument("input", help="OpenVAS XML file, IP address, URL, or file hash")
    parser.add_argument("--xml", action="store_true", help="Treat input as an OpenVAS XML file")
    args = parser.parse_args()

    try:
        if args.xml:
            if not os.path.exists(args.input):
                logger.error(f"XML file not found: {args.input}")
                raise FileNotFoundError(f"XML file not found: {args.input}")
            findings = parse_openvas(args.input)
            cases = []
            for finding in findings:
                ip = finding['ip']
                vt_data = None
                case_id = None
                severity = finding['severity']
                logger.debug(f"Processing finding: {finding['name']}, IP: {ip}, Severity: {severity}, Type: {type(severity)}")
                if ip != "N/A" and is_public_ip(ip):
                    logger.debug(f"Querying VirusTotal for public IP: {ip}")
                    vt_data = query_virustotal(ip, "ip")
                logger.debug(f"Evaluating severity: {severity} >= 4.8 = {severity >= 4.8}")
                if severity >= 4.8:
                    logger.debug(f"Severity {severity} meets threshold (>= 4.8), attempting to create case")
                    case_id = create_openvas_case(finding, vt_data)
                    if case_id:
                        logger.info(f"Case created for severity >= 4.8: {finding['name']} (ID: {case_id})")
                    else:
                        logger.error(f"Failed to create case for severity >= 4.8: {finding['name']}")
                elif vt_data and is_suspicious_vt(vt_data, "ip"):
                    logger.debug(f"Suspicious VirusTotal results, attempting to create case")
                    case_id = create_openvas_case(finding, vt_data)
                    if case_id:
                        logger.info(f"Case created for suspicious VT results: {finding['name']} (ID: {case_id})")
                    else:
                        logger.error(f"Failed to create case for suspicious VT results: {finding['name']}")
                else:
                    logger.info(f"Skipping case for IP {ip} (private: {not is_public_ip(ip)}, severity: {severity}, suspicious VT: {is_suspicious_vt(vt_data, 'ip') if vt_data else False})")
                if case_id:
                    cases.append({"finding": finding, "case_id": case_id})
            save_openvas_results(findings, cases)
            # Notify for each created case
            for c in cases:
                cid = c.get("case_id")
                finding = c.get("finding", {})
                if cid:
                    message = f"[TheHive] Case created: {finding.get('name', '')} (ID: {cid})\nIP: {finding.get('ip', '')} | Severity: {finding.get('severity', '')}"
                    os.system(f'echo "{message}" | notify --silent')
        else:
            input_value = args.input
            input_type = validate_input(input_value)
            vt_data = query_virustotal(input_value, input_type)
            case_id = None
            if is_suspicious_vt(vt_data, input_type):
                case_id = create_vt_case(input_value, input_type, vt_data)
                logger.info(f"Case created for suspicious VT results: {input_value} (ID: {case_id})")
            else:
                logger.info(f"No suspicious VirusTotal results for {input_type} {input_value}, skipping case creation")
            save_vt_results(input_value, input_type, vt_data, case_id)
            # Notify for VT case
            if case_id:
                if input_type == "ip" and vt_data and is_suspicious_vt(vt_data, input_type):
                    message = f"[TheHive] VT Case created: Suspicious Ip Analysis: {input_value}"
                else:
                    message = f"[TheHive] VT Case created: {input_value} (ID: {case_id})"
                os.system(f'echo "{message}" | notify --silent')
    except Exception as e:
        logger.error(f"Script failed: {e}")
        raise

if __name__ == "__main__":
    main()
