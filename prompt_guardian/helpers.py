import re
import iocextract


def extract_urls(text):
    extracted = []
    cleaned_text = re.sub(r'\s+', ' ', text)
    for url in iocextract.extract_iocs(cleaned_text, refang=True):
        extracted.append(url)
    return extracted
