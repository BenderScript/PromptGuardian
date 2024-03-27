from enum import Enum
from typing import Optional, List

from pydantic import BaseModel, Field


class CheckPromptRequest(BaseModel):
    text: str = Field(description="Prompt or text to be checked")
    extractedUrls: list[str] = Field(description="Unused")

    check_url: bool = True  # Default to true, perform URL check
    check_openai: bool = True  # Default to true, perform OpenAI check
    check_gemini: bool = True  # Default to true, perform Gemini check
    check_azure: bool = True  # Default to true, perform Azure check
    check_threats: bool = True  # Default to true, perform threat check


class URLHausRequest(BaseModel):
    url: str = Field(description="URL to be added to the DB")
    tags: Optional[List[str]] = None
    # site_categories indicate what type of site this is, for example, "Education", "Shopping", etc.
    threat: Optional[List[str]] = None


class LLMResult(BaseModel):
    azure: str = Field(description="Azure prompt injection detection result")
    gemini: str = Field(description="Gemini prompt injection detection result")
    openai: str = Field(description="OpenAI prompt injection detection result")


class CheckURLVerdictResult(BaseModel):
    target: str
    threat_level: Optional[str] = ""
    threat_categories: Optional[List[str]] = None
    # site_categories indicate what type of site this is, for example, "Education", "Shopping", etc.
    site_categories: Optional[List[str]] = None
    source: Optional[str] = ""


class CheckPromptResult(BaseModel):
    prompt_injection: LLMResult = Field(description="Prompt injection results for each LLM")
    url_verdict: List[CheckURLVerdictResult] = Field(description="URL verdict")
    threats: str = Field(description="DLP threat results")


class ThreatLevelType(Enum):
    QUESTIONABLE = 'questionable'
    UNKNOWN = 'unknown'
    UNTRUSTED = 'untrusted'


class SourceType(Enum):
    SYSTEM = "System"
    URLHAUS = "URLhaus"
