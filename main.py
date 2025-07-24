import argparse
import socket
import requests
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of public blacklists (feel free to expand)
BLACKLISTS = {
    "spamhaus": {
        "domain": "zen.spamhaus.org",
        "query_type": "domain",
    },
    "abuseipdb": {
        "domain": "check.abuseipdb.com",
        "query_type": "ip",
    },
    # Example RBLs. Can be added or removed
    "bl_spamcop": {
        "domain": "bl.spamcop.net",
        "query_type": "ip",
    },
    "psbl":{
        "domain": "psbl.surriel.com",
        "query_type": "ip"
    }
}


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Check an IP address or domain against public blacklists.")
    group = parser.add_mutually_exclusive_group(required=True)  # Enforce either IP or domain
    group.add_argument("-i", "--ip", help="The IP address to check.")
    group.add_argument("-d", "--domain", help="The domain to check.")
    parser.add_argument("-l", "--list", help="Specify a particular list instead of all blacklists", choices=BLACKLISTS.keys())

    return parser


def is_valid_ip(ip):
    """
    Validates if the provided string is a valid IPv4 address.
    Returns True if valid, False otherwise.
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False


def is_valid_domain(domain):
    """
    Validates if the provided string is a valid domain name.
    Returns True if valid, False otherwise.
    """
    try:
        # Basic domain validation (more robust validation might be needed)
        if not all(c.isalnum() or c in '-.' for c in domain):
            return False
        if domain.startswith('-') or domain.endswith('-'):
            return False
        socket.gethostbyname(domain) # Check if DNS can resolve the domain
        return True
    except socket.gaierror:
        return False


def check_blacklist(target, blacklist_name, blacklist_domain, query_type):
    """
    Checks if the given IP address or domain is listed on the specified blacklist.
    Returns True if listed, False otherwise.  Handles DNS errors gracefully.
    """
    try:
        if query_type == "ip":
            reversed_ip = ".".join(reversed(target.split(".")))
            query = f"{reversed_ip}.{blacklist_domain}"
        elif query_type == "domain":
            query = f"{target}.{blacklist_domain}"
        else:
            logging.error(f"Invalid query type: {query_type}")
            return False
        
        socket.gethostbyname(query)
        logging.info(f"{target} found on {blacklist_name} ({blacklist_domain})")
        return True
    except socket.gaierror:
        logging.debug(f"{target} not found on {blacklist_name} ({blacklist_domain})") # Debug log, not an error
        return False
    except Exception as e:
        logging.error(f"An error occurred while checking {blacklist_name}: {e}")
        return False


def main():
    """
    Main function to parse arguments, validate input, and check against blacklists.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    target = None
    if args.ip:
        if not is_valid_ip(args.ip):
            logging.error("Invalid IP address.")
            sys.exit(1)
        target = args.ip
    elif args.domain:
        if not is_valid_domain(args.domain):
            logging.error("Invalid domain name.")
            sys.exit(1)
        target = args.domain

    if not target:
        logging.error("No target specified.")
        sys.exit(1)

    if args.list:
      blacklists_to_check = {args.list: BLACKLISTS[args.list]}
    else:
      blacklists_to_check = BLACKLISTS

    is_listed = False
    for blacklist_name, blacklist_data in blacklists_to_check.items():
        try:
            listed = check_blacklist(target, blacklist_name, blacklist_data["domain"], blacklist_data["query_type"])
            if listed:
                print(f"{target} is listed on {blacklist_name} ({blacklist_data['domain']})")
                is_listed = True
            else:
                print(f"{target} is not listed on {blacklist_name} ({blacklist_data['domain']})")
        except Exception as e:
            logging.error(f"An error occurred while checking {blacklist_name}: {e}")

    if not is_listed:
        logging.info(f"{target} not listed on any checked blacklists.")
    else:
        logging.warning(f"{target} is listed on one or more blacklists.")


if __name__ == "__main__":
    main()