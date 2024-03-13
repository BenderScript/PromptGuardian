import asyncio
import os
import re
from http import HTTPStatus
from importlib import import_module

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from prompt_injection_bench.azure_openai_async_prompt_guard import AzureOpenAIAsyncPromptGuard
from prompt_injection_bench.gemini_async_prompt_guard import GeminiAsyncPromptGuard
from prompt_injection_bench.openai_async_prompt_guard import OpenAIAsyncPromptGuard
from pydantic import BaseModel, Field

from prompt_guardian.dependecies import URLListManager
from prompt_guardian.helpers import extract_urls, extract_domains
from prompt_guardian.llm_state import OpenAIState, GeminiState, AzureJailbreakState, LLMState

load_dotenv()


class CheckPromptRequest(BaseModel):
    text: str = Field(description="Prompt or text to be checked")
    extractedUrls: list[str] = Field(description="Unused")

    check_url: bool = True  # Default to true, perform URL check
    check_openai: bool = True  # Default to true, perform OpenAI check
    check_gemini: bool = True  # Default to true, perform Gemini check
    check_azure: bool = True  # Default to true, perform Azure check
    check_threats: bool = True  # Default to true, perform threat check


class URLAddRequest(BaseModel):
    url: str = Field(description="URL to be added to the DB")


class LLMResult(BaseModel):
    azure: str = Field(description="Azure prompt injection detection result")
    gemini: str = Field(description="Gemini prompt injection detection result")
    openai: str = Field(description="OpenAI prompt injection detection result")


class CheckPromptResult(BaseModel):
    prompt_injection: LLMResult = Field(description="Prompt injection results for each LLM")
    url_verdict: str = Field(description="URL verdict")
    threats: str = Field(description="DLP threat results")


def mount_static_directory(app: FastAPI):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    static_dir = os.path.join(base_dir, 'static')
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


prompt_guardian_app = FastAPI()

# Call the function to mount the static directory
mount_static_directory(prompt_guardian_app)


def get_class_instance():
    module_path = os.getenv("MODULE_PATH")
    class_name = os.getenv("CLASS_NAME")

    # Only proceed if both environment variables are set
    if module_path is not None and class_name is not None:
        try:
            module = import_module(module_path)
            class_ = getattr(module, class_name)
            return class_(env_path="../.env")
        except AttributeError:
            # Failing silently, you might want to log this for debugging purposes
            pass
        except ImportError:
            # Failing silently, you might want to log this for debugging purposes
            pass
    # Return None or a default behavior if the environment variables are not set
    return None


def init_llms():
    # Initialize the class instance and store it in the app state
    class_instance = get_class_instance()
    prompt_guardian_app.state.class_instance = class_instance

    prompt_guardian_app.state.openai = OpenAIState(prompt_guard=OpenAIAsyncPromptGuard(),
                                                   injection_attack=0, not_injection_attack=0, missed_attack=0)
    if prompt_guardian_app.state.openai.prompt_guard.enabled is False:
        print("No OpenAI API key found, OpenAI prompt injection detection is disabled")

    prompt_guardian_app.state.gemini = GeminiState(prompt_guard=GeminiAsyncPromptGuard(),
                                                   injection_attack=0, not_injection_attack=0, missed_attack=0)
    if prompt_guardian_app.state.gemini.prompt_guard.enabled is False:
        print("No Google API key found, gemini prompt injection detection is disabled")

    prompt_guardian_app.state.azure = AzureJailbreakState(prompt_guard=AzureOpenAIAsyncPromptGuard(),
                                                          injection_attack=0, not_injection_attack=0, missed_attack=0)
    if prompt_guardian_app.state.azure.prompt_guard.enabled is False:
        print("No OpenAI API key found, OpenAI prompt injection detection is disabled")


def init_urldb():
    url_manager: URLListManager = URLListManager()
    prompt_guardian_app.state.url_manager = url_manager
    asyncio.create_task(url_manager.periodic_update_url_list())


@prompt_guardian_app.on_event("startup")
async def startup_event():
    init_llms()


@prompt_guardian_app.on_event("startup")
async def start_infinite_task():
    init_urldb()


@prompt_guardian_app.get("/healthz")
def health_check():
    return {"status": "ok"}


# Serve HTML file from the root route
@prompt_guardian_app.get("/", response_class=HTMLResponse)
async def read_root():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    index_file_path = os.path.join(base_dir, "index.html")
    with open(index_file_path, "r") as file:
        return HTMLResponse(content=file.read())


@prompt_guardian_app.post("/add-url")
async def add_url(url_add_request: URLAddRequest, request: Request):
    url = url_add_request.url
    url_manager = request.app.state.url_manager

    # Logic to add the URL
    url_manager.add_url(url)  # Assuming you have a method `add_url` in URLListManager

    return {"status": "URL added to the list"}


@prompt_guardian_app.get("/urls")
async def add_url(request: Request):
    url_manager = request.app.state.url_manager  # Assuming you have a method `add_url` in URLListManager
    return {"urls": url_manager.get_urls()}


def check_url_status(prompt: str, url_manager):
    for u in extract_urls(prompt):
        if url_manager.check_url(u):
            return "URL(s) is in the abuse list"
    for u in extract_domains(prompt):
        if url_manager.check_url(u):
            return "URL(s) is in the abuse list"
    return "No malware URL(s) detected"


async def check_prompt_status(prompt: str, state: LLMState):
    if state.prompt_guard.enabled is False:
        return f"{state} Prompt Injection Detection disabled"
    else:
        status_code, response = await state.prompt_guard.generate_response(prompt=prompt)
        if status_code == HTTPStatus.OK.value:
            pattern_true = r'\btrue\b\.?'
            pattern_false = r'\bfalse\b\.?'

            matches = re.findall(pattern_true, response.lower())
            if len(matches) > 0:
                state.injection_attack += 1
                return "Prompt Injection Attack Detected"
            elif len(re.findall(pattern_false, response)) > 0:
                state.azure.not_injection_attack += 1
            else:
                state.missed_attack += 1
            return "No Prompt Injection Detected"
        elif status_code == 401:
            return response
        elif status_code == 429:
            return response
        elif 400 <= status_code < 500:
            return f"Client Error. Status code: {status_code}"
        elif 500 <= status_code < 600:
            return f"Server Error. Status code: {status_code}"
        else:
            print("Received an unexpected status code:", status_code)
            raise ValueError("Received an unexpected status code:", status_code)


def check_threats(prompt: str, class_instance):
    if class_instance:
        pdf_buffer = class_instance.create_pdf_from_string(prompt)
        verdict, threats, status_code = class_instance.send_pdf_buf_to_server(pdf_buffer)
        if status_code == HTTPStatus.OK.value:
            if len(threats) != 0:
                return ", ".join(threats)
            else:
                return "No Threats Detected"
        else:
            return "No connection to DLP Server"
    else:
        return "DLP Scanning is disabled"


@prompt_guardian_app.post("/check-prompt")
async def check_prompt(prompt_check_request: CheckPromptRequest, request: Request) -> CheckPromptResult:
    prompt = prompt_check_request.text
    url_manager = request.app.state.url_manager

    # default statuses - these will be returned to the client when the functionalities are not selected in the request
    url_status = "Prompt check for malware URLs is disabled per client request"
    openai_prompt_status = "Prompt injection detection with OpenAI is disabled per client request"
    gemini_prompt_status = "Prompt injection detection with Gemini is disabled per client request"
    azure_prompt_status = "Prompt injection detection with Azure is disabled per client request"
    threats = "Prompt check for DLP with Umbrella is disabled per client request"

    if prompt_check_request.check_url:
        if url_manager.enabled:
            print("checking URL")
            url_status = check_url_status(prompt, url_manager)
        else:
            url_status = "URL checking is disabled"

    if prompt_check_request.check_openai:
        openai_prompt_status = await check_prompt_status(prompt, prompt_guardian_app.state.openai)

    if prompt_check_request.check_gemini:
        gemini_prompt_status = await check_prompt_status(prompt, prompt_guardian_app.state.gemini)

    if prompt_check_request.check_azure:
        azure_prompt_status = await check_prompt_status(prompt, prompt_guardian_app.state.azure)

    if prompt_check_request.check_threats:
        threats = check_threats(prompt, request.app.state.class_instance)

    llm_result = LLMResult(azure=azure_prompt_status, gemini=gemini_prompt_status, openai=openai_prompt_status)
    result = CheckPromptResult(prompt_injection=llm_result, url_verdict=url_status, threats=threats)
    # print(result)
    return result
