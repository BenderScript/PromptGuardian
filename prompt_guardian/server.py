import asyncio
import os
from importlib import import_module

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from prompt_injection_bench.gemini_prompt_guard import GeminiPromptGuard
from prompt_injection_bench.openai_prompt_guard import OpenAIPromptGuard
from pydantic import BaseModel

from prompt_guardian.dependecies import URLListManager
from prompt_guardian.helpers import extract_urls

load_dotenv()


class PromptCheckRequest(BaseModel):
    text: str
    extractedUrls: list[str]  # Add this line to include the list of URLs


class URLAddRequest(BaseModel):
    url: str


openai_prompt_guard = OpenAIPromptGuard()
openai_prompt_detection_enabled = True
if openai_prompt_guard.client is None:
    openai_prompt_detection_enabled = False
    print("No OpenAI API key found, OpenAI prompt injection detection is disabled")

gemini_prompt_guard = GeminiPromptGuard()
gemini_prompt_detection_enabled = True
if openai_prompt_guard.client is None:
    gemini_prompt_detection_enabled = False
    print("No Google API key found, gemini prompt injection detection is disabled")

prompt_guardian_app = FastAPI()


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


# Dependency

@prompt_guardian_app.on_event("startup")
def startup_event():
    url_manager = URLListManager()
    prompt_guardian_app.state.url_manager = url_manager
    asyncio.create_task(url_manager.periodic_update_url_list())
    # Initialize the class instance and store it in the app state
    class_instance = get_class_instance()
    prompt_guardian_app.state.class_instance = class_instance


# Mount static directory
# Inside your FastAPI app, when setting up the static directory
base_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(base_dir, 'static')
prompt_guardian_app.mount("/static", StaticFiles(directory=static_dir), name="static")


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


def check_url_status(prompt: str, url_manager):
    urls_py = extract_urls(prompt)
    for url in urls_py:
        if url_manager.check_url(url):
            return "Malware URL(s)"
    return "No Malware URL(s)"


def check_openai_prompt_status(prompt: str):
    if openai_prompt_detection_enabled is False:
        return "OpenAI Prompt Injection Detection disabled"
    response = openai_prompt_guard.generate_response(prompt=prompt)
    if response.lower() == "this is a prompt injection attack":
        return "Prompt Injection Attack Detected"
    return "No Prompt Injection Detected"


def check_gemini_prompt_status(prompt: str):
    if gemini_prompt_detection_enabled is False:
        return "Gemini Prompt Injection Detection disabled"
    response = gemini_prompt_guard.generate_response(prompt=prompt)
    if response.lower() == "this is a prompt injection attack":
        return "Prompt Injection Attack Detected"
    return "No Prompt Injection Detected"


def check_threats(prompt: str, class_instance):
    if class_instance:
        pdf_buffer = class_instance.create_pdf_from_string(prompt)
        verdict, threats = class_instance.send_pdf_buf_to_server(pdf_buffer)
        if len(threats) != 0:
            return ", ".join(threats)
    return "No Threats Detected or DLP Disabled"


@prompt_guardian_app.post("/check-prompt")
async def check_prompt(prompt_check_request: PromptCheckRequest, request: Request):
    prompt = prompt_check_request.text
    url_manager = request.app.state.url_manager

    url_status = check_url_status(prompt, url_manager)
    openai_prompt_status = check_openai_prompt_status(prompt)
    gemini_prompt_status = check_gemini_prompt_status(prompt)
    threats = check_threats(prompt, request.app.state.class_instance)
    json_response = {
        "prompt_injection": {
            "openai": openai_prompt_status,
            "gemini": gemini_prompt_status
        },
        "url_verdict": url_status,
        "threats": threats
    }
    print(json_response)
    return json_response
