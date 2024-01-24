# Prompt Guardian

This is application that will check your prompt against a database of 
malicious URLs and whether it is considered prompt injection attack.

It uses OpenAI to check prompt injection attacks. Why? Because it's fun.
Seriously, it has very good guard rails to prevent you from doing dumb things. Therefore, 
if you use another LLM, your prompt will be checked against OpenAI.

Finally it checks your prompt for DLP (Data Loss Prevention). It uses an abstracted
API to check your prompt against a database.

## OpenAI API Key

You should have an environment variable called `OPENAI_API_KEY` with your OpenAI API key. Alternatively,
you can create a `.env` file on the project root directory with the following content:

```bash
OPENAI_API_KEY=<your-api-key>
```

## Installing Dependencies

```bash
pip3 install -r requirements.txt
```

## Running

On the project root directory, run the following command:

```bash
uvicorn prompt_guardian.server:prompt_guardian_app --reload --port 9001 
```

If Everything goes well, you should see the following page at http://127.0.0.1:9001


![Landing page](images/landing.png)
