import re

# https://gist.github.com/dperini/729294#gistcomment-1480671

URL_REGEX = re.compile(
    # Same pattern as before but without ^ and $
    r"(?:(?:(?:https?|ftp):)?//)"
    r"(?:\S+(?::\S*)?@)?"
    r"(?:"
    r"(?!(?:10|127)(?:\.\d{1,3}){3})"
    r"(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})"
    r"(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})"
    r"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])"
    r"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}"
    r"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))"
    r"|"
    r"(?:"
    r"(?:"
    r"[a-z0-9\u00a1-\uffff]"
    r"[a-z0-9\u00a1-\uffff_-]{0,62}"
    r")?"
    r"[a-z0-9\u00a1-\uffff]\."
    r")+"
    r"(?:[a-z\u00a1-\uffff]{2,}\.?)"
    r")"
    r"(?::\d{2,5})?"
    r"(?:[/?#]\S*)?"
    , re.UNICODE | re.I
)

def extract_urls(text):
    urls = URL_REGEX.findall(text)
    return urls
