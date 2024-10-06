import readline
import glob
import requests
import pyfiglet
from termcolor import colored

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
        error_indicators = ["You have an error in your SQL syntax", "Warning: mysql_", "Unclosed quotation mark", "SQL error", "ORA-"]
        for error in error_indicators:
            if error in response.text:
                return True
        return False
    except requests.exceptions.RequestException:
        return False

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

# Function to process a wordlist and test SQLi vulnerabilities
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

# Function to display stylish information
def display_info():
    # Smaller dotted lines with "Created by" in green
    created_by = colored("...... Created by ......", "green")
    
    # Use pyfiglet to create a fancy banner for "Ankit Jha"
    name_banner = pyfiglet.figlet_format("Ankit Jha")
    
    # Use termcolor to add color to the email display
    email = colored("Email: ankitjha883@gmail.com", "cyan")
    
    print(created_by)  # Display "Created by" in small green dotted lines
    print(colored(name_banner, "green"))  # Display name in green color
    print(email)  # Display email in cyan color
    
    # ASCII Art Coffin for Credits
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
    print(colored(credit_coffin, "red"))  # Display credit coffin in red

# Main function to prompt for inputs
def main():
    # Display information at the start
    display_info()

    print("\nWelcome to the Vulnerability Detection Tool")
    
    # Prompt for URL
    url = input("Enter the URL to scan: ")

    # Prompt for XSS wordlist with tab completion
    xss_wordlist = input("Enter the path to the XSS wordlist file (Tab to auto-complete, or leave empty if not testing XSS): ")

    # Prompt for SQLi wordlist with tab completion
    sqli_wordlist = input("Enter the path to the SQLi wordlist file (Tab to auto-complete, or leave empty if not testing SQL Injection): ")

    # Process XSS wordlist if provided
    if xss_wordlist:
        process_xss_wordlist(url, xss_wordlist)

    # Process SQLi wordlist if provided
    if sqli_wordlist:
        process_sqli_wordlist(url, sqli_wordlist)

# Run the main function when the script is executed
if __name__ == "__main__":
    main()
