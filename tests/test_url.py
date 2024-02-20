import unittest
from prompt_guardian.server import prompt_guardian_app, startup_event
from fastapi.testclient import TestClient


class TestURLs(unittest.IsolatedAsyncioTestCase):

    def set_providers(self, client):
        # Assuming each provider can be enabled individually
        state = client.app.state
        state.openai.prompt_guard.enabled = False
        state.azure.prompt_guard.enabled = False
        state.gemini.prompt_guard.enabled = False

    async def add_remove_url(self, client, url, add=True):
        if add:
            # Add the URL
            response = client.post("/add-url", json={"url": url})
        else:
            # Remove the URL (if there's an endpoint for it)
            response = client.post("/remove-url", json={"url": url})

    async def test_check_url_in_abuse_list(self):
        test_url = "http://example.com/malicious"
        # Add URL to the list

        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            self.set_providers(client)
            await self.add_remove_url(client, test_url, add=True)
            response = client.post("/check-prompt"
                                   , json={"text": test_url,
                                           "extractedUrls": [""]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual("URL(s) is in the abuse list", response.json().get("url_verdict"))

            # Remove the URL from the list (optional)
            await self.add_remove_url(client, test_url, add=False)

    async def test_check_url_not_in_abuse_list(self):
        test_url = "http://example.com/safe"
        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            self.set_providers(client)
            response = client.post("/check-prompt"
                                   , json={"text": test_url,
                                           "extractedUrls": [""]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual("No malware URL(s) detected", response.json().get("url_verdict"))

    async def test_check_url_in_abuse_list_full_circle(self):
        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            self.set_providers(client)
            response = client.get("/urls")
            url_dict = response.json()
            url = url_dict.get("urls")[0]
            response = client.post("/check-prompt"
                                   , json={"text": url,
                                           "extractedUrls": [""]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual("URL(s) is in the abuse list", response.json().get("url_verdict"), f"URL: {url}")
