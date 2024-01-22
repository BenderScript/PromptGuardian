import asyncio
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from prompt_injection_bench.openai_prompt_guard import OpenAIPromptGuard
from pydantic import BaseModel

from prompt_guardian.dependecies import URLListManager
from prompt_guardian.helpers import extract_urls


class PromptCheckRequest(BaseModel):
    text: str


class URLAddRequest(BaseModel):
    url: str


openai_prompt_guard = OpenAIPromptGuard()

prompt_guardian_app = FastAPI()


# Dependency

@prompt_guardian_app.on_event("startup")
def startup_event():
    url_manager = URLListManager()
    prompt_guardian_app.state.url_manager = url_manager
    asyncio.create_task(url_manager.periodic_update_url_list())


# Mount static directory
prompt_guardian_app.mount("/static", StaticFiles(directory="static"), name="static")


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
async def check_url(url_check_request: PromptCheckRequest, request: Request):
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
    if response == "this is a prompt injection attack":
        prompt_status = "Prompt Injection Attack"
    else:
        prompt_status = "No Prompt Injection Detected"

    return {"status": prompt_status + ", " + url_status}


