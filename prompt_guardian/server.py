import asyncio
import os
from importlib import import_module
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from prompt_injection_bench.openai_prompt_guard import OpenAIPromptGuard
from pydantic import BaseModel

from prompt_guardian.dependecies import URLListManager
from prompt_guardian.helpers import extract_urls

load_dotenv()


class PromptCheckRequest(BaseModel):
    text: str


class URLAddRequest(BaseModel):
    url: str


openai_prompt_guard = OpenAIPromptGuard()

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
    with open("index.html", "r") as file:
        return HTMLResponse(content=file.read())


@prompt_guardian_app.post("/add-url")
async def add_url(url_add_request: URLAddRequest, request: Request):
    url = url_add_request.url
    url_manager = request.app.state.url_manager

    # Logic to add the URL
    url_manager.add_url(url)  # Assuming you have a method `add_url` in URLListManager

    return {"status": "URL added to the list"}


@prompt_guardian_app.post("/check-prompt")  # Note the change to a POST request
async def check_url(url_check_request: PromptCheckRequest, request: Request, class_instance: Any = Depends(get_class_instance)):
    prompt = url_check_request.text
    urls = extract_urls(prompt)
    url_manager = request.app.state.url_manager
    for url in urls:
        if url_manager.check_url(url):
            url_status = "Malware URL(s)"
            break
    else:
        url_status = "No Malware URL(s)"

    response = openai_prompt_guard.generate_response(prompt=prompt)
    if response.lower() == "this is a prompt injection attack":
        prompt_status = "Prompt Injection Attack"
    else:
        prompt_status = "No Prompt Injection Detected"

    verdict = ""
    if class_instance:
        pdf_buffer = class_instance.create_pdf_from_string(prompt)
        verdict = class_instance.send_pdf_to_server(pdf_buffer)

    return {"status": prompt_status + ", " + url_status + ", " + verdict}
