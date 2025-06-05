import json
import os
import random
import requests
import string
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")


custom_pivots=[
  {
    "title": "Google Search",
    "description": "Search Google for {obs_value}",
    "url": "https://www.google.com/search?q={obs_value}",
    "id-prefix": "aiai-nollm-google",
    "type": ["all"]
  },
  {
    "title": "DuckDuckGo Search",
    "description": "Search DuckDuckGo for {obs_value}",
    "url": "https://duckduckgo.com/?q={obs_value}",
    "id-prefix": "aiai-nollm-duckduckgo",
    "type": ["ip", "domain"]
  }
]


app = Flask(__name__)

def country_code_to_flag(country_code):
    """
    Converts a country code to its corresponding emoji flag.
    Args:
        country_code (str): The two-letter country code.
    Returns:
        str: The emoji flag for the country or an empty string if the code is invalid.
    """
    if not country_code:
        return ""
    return "".join(chr(ord(c.upper()) + 127397) for c in country_code)

def get_ip_info(ip_address):
    """
    Retrieves information about an IP address using the Free IP API.
    Args:
        ip_address (str): The IP address to query.
    Returns:
        dict: A dictionary containing information about the IP address, including location and country.
    """
    url = f"https://freeipapi.com/api/json/{ip_address}"
    response = requests.get(url)

    if response.status_code == 204:
        return {
            "id": f"aiai-prefetch-ip-info-{ip_address}",
            "title": "No IP Info Found",
            "description": f"No data found for {ip_address} at IP Info",
            "url": url,
        }

    response_data = response.json()
    description = "No vendor details available"
    title = "IP Info:"

    if response_data:
        country_flag = country_code_to_flag(response_data.get("countryCode"))
        country_code = response_data.get("countryCode", "")
        if "countryName" in response_data:
            title = (
                f'IP Geo: {country_flag} {country_code} ({response_data["countryName"]})'
            )
        description = f'IP Geolocation info for {ip_address}: Location: {response_data.get("cityName", "Unknown City")}, {response_data.get("countryName", "Unknown Country")}'

    return {
        "id": f"ref-aiai-prefetch-ip-info-{ip_address}",
        "title": title,
        "description": description,
        "url": url,
    }

def get_mac_vendor_info(mac_address):
    """
    Retrieves vendor information for a given MAC address using the Mac Vendor Lookup API.
    Args:
        mac_address (str): The MAC address to query.
    Returns:
        dict: A dictionary containing vendor information or a message if no vendor is found.
    """
    url = f'https://www.macvendorlookup.com/api/v2/{mac_address.replace("-", ":")}'
    response = requests.get(url)

    if response.status_code == 204:
        return {
            "id": f"aiai-prefetch-mac-vendor-lookup-{mac_address}",
            "title": "No Vendor Found",
            "description": f"No vendor found for MAC address {mac_address} at Mac Vendor Lookup",
            "url": url,
        }

    vendor_data = response.json()
    description = "No vendor details available"
    if vendor_data and isinstance(vendor_data, list) and len(vendor_data) > 0:
        description = f'MAC address {mac_address} has Vendor OUI: {vendor_data[0]["company"]}'

    return {
        "id": f"aiai-prefetch-mac-vendor-lookup-{mac_address}",
        "title": f'Vendor: {vendor_data[0]["company"]}',
        "description": description,
        "url": url,
    }

def get_reverse_dns_hackertarget(ip_address):
    """
    Retrieves reverse DNS information for a given IP address using the HackerTarget API.
    Args:
        ip_address (str): The IP address to query.
    Returns:
        dict: A dictionary containing reverse DNS information or a message if no data is found.
    """
    url = f"https://api.hackertarget.com/reversedns/?q={ip_address}"
    response = requests.get(url)

    if response.status_code != 200:
        return {
            "id": f"aiai-prefetch-reverse-dns-{ip_address}",
            "title": f"No Reverse DNS Found",
            "description": f"No reverse DNS found for IP address {ip_address}",
            "url": url,
        }
    response_data = response.text.split(" ")[1]
    title = f'Reverse DNS: {(response_data) if response_data else "Unknown"}'
    description = f'Reverse DNS data for IP address {ip_address}: {response_data if response_data else "Unknown"}' 

    return {
        "id": f"aiai-prefetch-reverse-dns-{ip_address}",
        "title": title,
        "description": description,
        "url": url,
    }

def get_asn_info(ip_address):
    """
    Retrieves ASN (Autonomous System Number) information for a given IP address using the HackerTarget API.
    Args:
        ip_address (str): The IP address to query.
    Returns:
        dict: A dictionary containing ASN information or a message if no data is found.
    """
    url = f"https://api.hackertarget.com/aslookup/?q={ip_address}&output=json"
    response = requests.get(url)

    if response.status_code != 200:
        return {
            "id": f"aiai-prefetch-asn-info-{ip_address}",
            "title": "No ASN Info Found",
            "description": f"No ASN info found for IP address {ip_address}",
            "url": url,
        }

    try:
        response_data = response.json()
        asn = response_data.get("asn", "Unknown")

        ripe_url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
        org_response = requests.get(ripe_url)
        org_json = org_response.json() if org_response.status_code == 200 else None

        org_name = (
            org_json.get("data", {}).get("holder", "")
            if org_json
            else response_data.get("org", "Unknown Organization")
        )
        org_name = org_name.split(" - ")[-1]

        title = f"ASN Info: {asn}/{org_name}"
        description = (
            f"ASN info for IP address {ip_address}: | "
            f"ASN: {asn} | "
            f'Range: {response_data.get("asn_range", "Unknown")} | '
            f"Organization: {org_name}"
        )

        return {
            "id": f"aiai-prefetch-asn-info-{ip_address}",
            "title": title,
            "description": description,
            "url": url,
        }
    except Exception as e:
        return {
            "id": f"aiai-prefetch-asn-info-{ip_address}",
            "title": "ASN Info: Error",
            "description": f"Error parsing ASN info for {ip_address}",
            "url": url,
        }

def get_domain_info(domain):
    """
    Retrieves WHOIS information for a given domain using the DomainTools API.
    Args:
        domain (str): The domain to query.
    Returns:
        dict: A dictionary containing WHOIS information or a message if no data is found.
    """
    url = f"https://api.domaintools.com/v1/domaintools.com/whois/{domain}"
    response = requests.get(url)
    if response.status_code != 200:
        return {
            "id": f"aiai-prefetch-domain-info-{domain}",
            "title": f"No WHOIS Info Found",
            "description": f"No WHOIS info found for {domain}",
            "url": url,
        }
    response_json = json.loads(response.text)["response"]
    registrant = response_json.get("registrant", "Unknown")
    created = response_json["registration"].get("created", "Unknown")
    expires = response_json["registration"].get("expires", "Unknown")
    registrar = response_json["registration"].get("registrar", "Unknown")
    return {
        "id": f"aiai-prefetch-domain-info-{domain}",
        "title": f"WHOIS Info: {registrant}",
        "description": f"WHOIS for {domain}: Registrant: {registrant}\nCreated: {created} \nExpires: {expires} \nRegistrar: {registrar}",
        "url": url,
    }

def normalize_observable(observable):
    """
    Normalizes the observable type to a human-readable format.
    Args:
        observable (dict): The observable to normalize.
    Returns:
        str: The normalized observable type.
    """
    if observable['type'] == 'ip':
        return "IP Address"
    if observable['type'] == 'domain':
        return "Domain"
    if observable['type'] == 'mac_address':
        return "MAC Address"

def add_brave_search(observable):
    """
    Adds a Brave search link for the given observable.
    Args:
        observable (dict): The observable to search for.
    Returns:
        dict: A dictionary containing the Brave search link.
    """
    obs_type = normalize_observable(observable)
    obs_value = observable['value']
    prompt = f"I am a security researcher and I have come across the {obs_type} {obs_value}. Can you please provide me with more information about it?"
    url = f'https://search.brave.com/search?q={prompt}&source=llmSuggest&summary=1'
    return {
        'id': f'aiai-nollm-brave',
        'title': f'Public Brave LLM AI Search',
        "description": 'Search with Brave Leo LLM',
        'url': url
    }

def query_virustotal_hash(hash_value):
    """
    Queries VirusTotal for information about a given hash value.
    Args:
        hash_value (str): The hash value to query.
    Returns:
        list: A list of dictionaries containing information about the hash value.
    """
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }
    response = requests.get(url, headers=headers).json()
    results = []
    if response.get('data', {}).get('links', {}).get('self'):
        results.append({
            'id':'aiai-virustotal-file-search',
            'title':'VirusTotal Link',
            'description':"",
            'url': f"https://www.virustotal.com/gui/file/{hash_value}"
        })
    if response.get('data', {}).get('attributes', {}).get('type_description'):
        results.append({
            'id':'aiai-prefetch-virustotal-file-search-type',
            'title': f'File Type: {response["data"]["attributes"]["type_description"]}',
            'description':f'{hash_value} is a {response["data"]["attributes"]["type_description"]}',
            'url': ""
        })
    if response.get('data', {}).get('attributes', {}).get('size'):
        results.append({
            'id':'aiai-prefetch-virustotal-file-search-size',
            'title': f'File Size: {response["data"]["attributes"]["size"]} bytes',
            'description':f'{hash_value} is {response["data"]["attributes"]["size"]} bytes in size',
            'url': ""
        })
    if response.get('data', {}).get('attributes', {}).get('last_analysis_stats'):
        malicious = response['data']['attributes']['last_analysis_stats']['malicious']
        undetected = response['data']['attributes']['last_analysis_stats']['undetected']
        results.append({
            'id':'aiai-prefetch-virustotal-file-search-stats',
            'title': f'Analysis Stats: {malicious}/{undetected+malicious} malicious',
            'description': f'{hash_value} is {malicious}/{undetected+malicious} malicious',
            'url': ""
        })
    return results

def get_certificate_info(domain):
    """
    Retrieves certificate information for a given domain using the CRT.sh API.
    Args:
        domain (str): The domain to query.
    Returns:
        dict: A dictionary containing certificate information or a message if no data is found.
    """
    url = f"https://crt.sh/json?q={domain}"
    r = requests.get(url)

    domains = set()
    try:
        for cert in r.json():
            if 'common_name' in cert:
                parts = cert['common_name'].split('.')
                if len(parts) >= 2:
                    if len(parts) >= 3 and (parts[-2] == 'co' or parts[-2] == 'com'):
                        domains.add('.'.join(parts[-3:]))
                    else:
                        domains.add('.'.join(parts[-2:]))

        domains_str = ', '.join(sorted(domains)) if domains else 'No domains found'

        return {
            'id': 'aiai-prefetch-crtsh-cert-checker',
            'title': 'CRT.sh Certificate Search',
            'description': f"The certificate for {domain} also serves the following associated domains: {domains_str}",
            'url': url
        }
    except Exception as e:
        return {
            'id': 'aiai-prefetch-crtsh-cert-checker',
            'title': 'CRT.sh Certificate Search error',
            'description': f"Error processing certificate data for {domain}",
            'url': url
        }

@app.route('/health', methods=['GET', 'POST'])
def health_check():
    """
    Health check endpoint to verify the service is running.
    Returns:
        json: A JSON object indicating the service status.
    """
    return jsonify({"data": {"status": "ok"}})

@app.route('/observe/observables', methods=['GET', 'POST'])
def observe_observables():
    """
    Placeholder, if we want to add functionality to Investigations
    """
    return jsonify({"data": {}})

@app.errorhandler(404)
def page_not_found(error):
    return jsonify({
        "error": "Not Found",
        "requested_url": request.url
    }), 404

@app.route('/refer/observables', methods=['POST'])
def refer_observables():
    """
    Endpoint to refer observables and retrieve related information.
    Returns:
        json: A JSON object containing information about the observables.
    """
    observables = request.get_json()
    relay_output = []

    # Check for entries in custom_pivots
    if custom_pivots:
     for item in custom_pivots:
      for observable in observables:
       if 'all' in item['type'] or observable['type'] in item['type']:
        relay_output.append({
         'id': f"{item['id-prefix']}-{observable['type']}-{observable['value']}",
         'title': item['title'],
         'description': f"{item['description']}".format(obs_value=observable['value'], obs_type=observable['type']),
         'url': f"{item['url']}{observable['value']}"
         })
    for observable in observables:
        if observable['type'] == 'mac_address':
            relay_output.append(get_mac_vendor_info(observable['value']))
        if observable['type'] == 'ip':
            relay_output.append(get_ip_info(observable['value']))
            relay_output.append(get_asn_info(observable['value']))
            relay_output.append(get_reverse_dns_hackertarget(observable['value']))
        if observable['type'] == 'domain':
            relay_output.append(get_domain_info(observable['value']))
            relay_output.append(get_certificate_info(observable['value']))
        if observable['type'] in ["sha256","sha1","md5"]:
            results = query_virustotal_hash(observable['value'])
            for result in results:
                relay_output.append(result)
        relay_output.append(add_brave_search(observable))

    return jsonify({'data': relay_output})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
