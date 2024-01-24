import re

# https://gist.github.com/dperini/729294#gistcomment-1480671


URL_REGEX = re.compile(
    r"(https?:\/\/"  # Protocol
    r"(?:\S+(?::\S*)?@)?"  # User:pass authentication (optional)
    r"(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"  # IP address
    r"|"
    r"(?:"  # Start of group for hostnames
    r"[a-z0-9\u00a1-\uffff]"  # Unicode characters in hostnames
    r"[a-z0-9\u00a1-\uffff_-]{0,62}"  # Hostname characters
    r")?"
    r"[a-z0-9\u00a1-\uffff]\."  # Unicode characters in domain
    r"+"  # One or more domain parts
    r"(?:[a-z\u00a1-\uffff]{2,}\.?)"  # TLD
    r")"
    r"(?::\d{2,5})?"  # Port (optional)
    r"(?:[/?#]\S*)?)",  # Path (optional)
    re.IGNORECASE  # Case-insensitive flag
)


def extract_urls(text):
    urls = URL_REGEX.findall(text)
    return urls
