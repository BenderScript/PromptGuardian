from pydantic import BaseModel
from prompt_injection_bench.azure_openai_async_prompt_guard import AzureOpenAIAsyncPromptGuard
from prompt_injection_bench.gemini_async_prompt_guard import GeminiAsyncPromptGuard
from prompt_injection_bench.openai_async_prompt_guard import OpenAIAsyncPromptGuard


class LLMState(BaseModel, arbitrary_types_allowed=True):
    pass


class OpenAIState(LLMState, arbitrary_types_allowed=True):
    prompt_guard: OpenAIAsyncPromptGuard
    injection_attack: int
    not_injection_attack: int
    missed_attack: int

    def __str__(self):
        return "OpenAI"


class GeminiState(LLMState, arbitrary_types_allowed=True):
    prompt_guard: GeminiAsyncPromptGuard
    injection_attack: int
    not_injection_attack: int
    missed_attack: int

    def __str__(self):
        return "Gemini"


class AzureJailbreakState(LLMState, arbitrary_types_allowed=True):
    prompt_guard: AzureOpenAIAsyncPromptGuard
    injection_attack: int
    not_injection_attack: int
    missed_attack: int

    def __str__(self):
        return "Azure"
