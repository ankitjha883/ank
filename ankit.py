import readline
import glob
import requests
import pyfiglet
from termcolor import colored
import dns.resolver

# Enable tab completion for file paths
def complete(text, state):
    return (glob.glob(text + '*') + [None])[state]

# Set up the tab completion for input
readline.set_completer(complete)
readline.parse_and_bind('tab: complete')

# Function to check for XSS vulnerability
def check_xss_vulnerability(url, payload):
    try:
        response = requests.get(url + payload, timeout=5)
        if payload in response.text:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False

# Function to check for SQL Injection vulnerability
def check_sql_injection_vulnerability(url, payload):
    try:
        response = requests.get(url + payload, timeout=5)
        error_indicators = ["You have an error in your SQL syntax", "Warning: mysql_", 
                            "Unclosed quotation mark", "SQL error", "ORA-"]
        for error in error_indicators:
            if error in response.text:
                return True
        return False
    except requests.exceptions.RequestException:
        return False

# Function to check for LFI vulnerability
def check_lfi_vulnerability(url, payload):
    try:
        response = requests.get(url + payload, timeout=5)
        # Check for known sensitive content
        if "root:x:" in response.text or "bin:" in response.text:  # Example indicators
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False

# Function to find subdomains
def find_subdomains(domain, subdomain_list_file):
    print(f"Finding subdomains for {domain} using wordlist: {subdomain_list_file}...\n")
    try:
        with open(subdomain_list_file, 'r') as file:
            subdomains = file.readlines()
            for subdomain in subdomains:
                subdomain = subdomain.strip()
                full_domain = f"{subdomain}.{domain}"
                try:
                    # Attempt to resolve the subdomain
                    dns.resolver.resolve(full_domain)
                    print(f"[Subdomain Found] {full_domain}")
                except dns.resolver.NoAnswer:
                    print(f"[Subdomain Not Found] {full_domain}")
                except dns.resolver.NXDOMAIN:
                    print(f"[Subdomain Not Found] {full_domain}")
                except Exception as e:
                    print(f"[Error] {full_domain}: {e}")
    except FileNotFoundError:
        print(f"Error: Subdomain wordlist file '{subdomain_list_file}' not found.")

# Function to get HTTP status code
def check_http_status_code(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"[HTTP Status Code] {url}: 200 OK")
    except requests.exceptions.RequestException:
        pass  # If the request fails, do nothing

# Function to process a wordlist and test XSS vulnerabilities
def process_xss_wordlist(url, wordlist_file):
    print(f"Processing XSS wordlist: {wordlist_file}...\n")
    try:
        with open(wordlist_file, 'r') as file:
            words = file.readlines()
            for word in words:
                word = word.strip()
                # Test for XSS
                xss_found = check_xss_vulnerability(url, word)
                if xss_found:
                    print(f"[XSS Found] Payload: {word}")
                else:
                    print(f"[XSS Not Found] Payload: {word}")
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_file}' not found.")

# Function to process a wordlist and test SQL Injection vulnerabilities
def process_sqli_wordlist(url, wordlist_file):
    print(f"Processing SQLi wordlist: {wordlist_file}...\n")
    try:
        with open(wordlist_file, 'r') as file:
            words = file.readlines()
            for word in words:
                word = word.strip()
                # Test for SQL Injection
                sqli_found = check_sql_injection_vulnerability(url, word)
                if sqli_found:
                    print(f"[SQLi Found] Payload: {word}")
                else:
                    print(f"[SQLi Not Found] Payload: {word}")
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_file}' not found.")

# Function to process a wordlist and test LFI vulnerabilities
def process_lfi_wordlist(url, wordlist_file):
    print(f"Processing LFI wordlist: {wordlist_file}...\n")
    try:
        with open(wordlist_file, 'r') as file:
            words = file.readlines()
            for word in words:
                word = word.strip()
                # Test for LFI
                lfi_found = check_lfi_vulnerability(url, word)
                if lfi_found:
                    print(f"[LFI Found] Payload: {word}")
                else:
                    print(f"[LFI Not Found] Payload: {word}")
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_file}' not found.")

# Function to display stylish information
def display_info():
    created_by = colored("...... Created by ......", "green")
    name_banner = pyfiglet.figlet_format("Ankit Jha")
    email = colored("Email: ankitjha883@gmail.com", "cyan")
    
    print(created_by)
    print(colored(name_banner, "green"))
    print(email)

    credit_coffin = """
    ______________________________
   /  Credit:  coffin             \\
  /   Created: Ankit Jha           \\
 /    Email: ankitjha883@gmail.com \\
/__________________________________\\
|                                  |
|   Vulnerability Detection Tool   |
|__________________________________|
    """
    print(colored(credit_coffin, "red"))

# Main function to prompt for inputs
def main():
    display_info()
    print("\nWelcome to the Vulnerability Detection Tool")
    
    # Prompt for URL
    url = input("Enter the URL to scan (e.g., example.com): ")

    # Check HTTP status code
    check_http_status_code(url)

    # Prompt for XSS wordlist with tab completion
    xss_wordlist = input("Enter the path to the XSS wordlist file (Tab to auto-complete, or leave empty if not testing XSS): ")

    # Prompt for SQLi wordlist with tab completion
    sqli_wordlist = input("Enter the path to the SQLi wordlist file (Tab to auto-complete, or leave empty if not testing SQL Injection): ")

    # Prompt for LFI wordlist with tab completion
    lfi_wordlist = input("Enter the path to the LFI wordlist file (Tab to auto-complete, or leave empty if not testing LFI): ")

    # Prompt for subdomain wordlist
    subdomain_wordlist = input("Enter the path to the subdomain wordlist file (Tab to auto-complete, or leave empty if not testing subdomains): ")

    # Process XSS wordlist if provided
    if xss_wordlist:
        process_xss_wordlist(url, xss_wordlist)

    # Process SQLi wordlist if provided
    if sqli_wordlist:
        process_sqli_wordlist(url, sqli_wordlist)

    # Process LFI wordlist if provided
    if lfi_wordlist:
        process_lfi_wordlist(url, lfi_wordlist)

    # Process subdomain wordlist if provided
    if subdomain_wordlist:
        find_subdomains(url, subdomain_wordlist)

# Run the main function when the script is executed
if __name__ == "__main__":
    main()
