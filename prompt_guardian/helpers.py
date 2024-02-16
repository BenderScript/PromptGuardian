import re
import iocextract


def extract_urls(text):
    extracted = []
    cleaned_text = re.sub(r'\s+', ' ', text)
    for url in iocextract.extract_iocs(cleaned_text, refang=True):
        extracted.append(url)
    return extracted


def extract_domains(text):
    # This regex pattern matches domains with alphanumeric characters and hyphens, separated by dots.
    # It will match domains like '172-234-120-102.ip.linodeusercontent.com'
    pattern = r'\b(?:[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b'
    domains = re.findall(pattern, text)
    return domains