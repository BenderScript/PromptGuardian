import re
import iocextract


# https://gist.github.com/dperini/729294#gistcomment-1480671


# URL_REGEX = re.compile(
#     r"(?:https?:\/\/)?"  # Protocol (optional)
#     r"(?:[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*@)?"  # User:pass authentication (optional)
#     r"(?:"
#     r"(?:\d{1,3}\.){3}\d{1,3}"  # IP address
#     r"|"
#     r"(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,24}"  # Domain name, allowing TLDs up to 24 characters
#     r")"
#     r"(?::\d{2,5})?"  # Port (optional)
#     r"(?:\/[a-zA-Z0-9\/_-]*)?",  # Path (optional)
#     re.IGNORECASE  # Case-insensitive flag
# )
#
#
# def extract_urls(text):
#     cleaned_text = re.sub(r'\s+', ' ', text)
#     urls = URL_REGEX.findall(cleaned_text)
#     # Extract IP addresses or domains
#     regex = (r"(?:https?:\/\/)?(?:[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*@)?((?:\d{1,3}\.){3}\d{1,"
#              r"3}|(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,24})(?::\d{2,5})?(?:\/[a-zA-Z0-9\/_-]*)?")
#     extracted = []
#     for url in urls:
#         match = re.search(regex, url)
#         if match:
#             extracted.append(match.group(1))
#     return extracted


def extract_urls(text):
    extracted = []
    cleaned_text = re.sub(r'\s+', ' ', text)
    for url in iocextract.extract_iocs(cleaned_text, refang=True):
        extracted.append(url)
    return extracted
