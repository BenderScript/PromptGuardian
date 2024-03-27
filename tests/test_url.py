import json
import unittest
from prompt_guardian.server import prompt_guardian_app, startup_event
from prompt_guardian.models import URLHausRequest, ThreatLevelType, SourceType
from fastapi.testclient import TestClient


class TestURLs(unittest.IsolatedAsyncioTestCase):

    def set_providers(self, client):
        # Assuming each provider can be enabled individually
        state = client.app.state
        state.openai.prompt_guard.enabled = False
        state.azure.prompt_guard.enabled = False
        state.gemini.prompt_guard.enabled = False

    async def add_remove_url(self, client, urlRequest: URLHausRequest, add=True):
        if add:
            # Add the URL
            response = client.post("/add-url", json=json.dumps(urlRequest.dict()))
        else:
            # Remove the URL (if there's an endpoint for it)
            response = client.post("/remove-url", json={"url": urlRequest.get("url")})
        return response

    async def test_check_url_in_abuse_list(self):
        test_url = "http://example.com/malicious"
        # Add URL to the list

        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            self.set_providers(client)
            urlRequest = URLHausRequest(url=test_url,
                                        tags=["elf", "win32"], threat=["malware_download"])
            client.post("/add-url", json=urlRequest.dict())
            response = client.post("/check-prompt"
                                   , json={"text": test_url,
                                           "extractedUrls": [""],
                                           "check_openai": False,
                                           "check_gemini": False,
                                           "check_azure": False,
                                           "check_threats": False,
                                           "check_url": True
                                           })
            self.assertEqual(response.status_code, 200)
            expected_url_verdict = [{'site_categories': ['malware_download'],
                                     'source': 'URLhaus',
                                     'target': 'example.com',
                                     'threat_categories': ['elf', 'win32'],
                                     'threat_level': 'untrusted'}]
            self.assertEqual(expected_url_verdict, response.json().get("url_verdict"))

    async def test_check_url_not_in_abuse_list(self):
        test_url = "http://example.com/safe"
        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            self.set_providers(client)
            response = client.post("/check-prompt"
                                   , json={"text": test_url,
                                           "extractedUrls": [""],
                                           "check_openai": False,
                                           "check_gemini": False,
                                           "check_azure": False,
                                           "check_threats": False,
                                           "check_url": True
                                           })
            self.assertEqual(response.status_code, 200)
            self.assertEqual([], response.json().get("url_verdict"))

    async def test_check_url_in_abuse_list_full_circle(self):
        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            self.set_providers(client)
            response = client.get("/urls")
            url_dict = response.json()
            urls = url_dict.get("urls")
            for url in urls:
                response = client.post("/check-prompt"
                                       , json={"text": url,
                                               "extractedUrls": [""],
                                               "check_openai": False,
                                               "check_gemini": False,
                                               "check_azure": False,
                                               "check_threats": False,
                                               "check_url": True
                                               })
                self.assertEqual(response.status_code, 200)
                response_data = response.json().get("url_verdict")[0]  # Assuming there's always one item in the list
                expected_url = {
                    "target": url,
                    "threat_level": "untrusted",
                    "source": "URLhaus"
                }

                self.assertEqual(expected_url["target"], response_data["target"], f"URL: {url}")
                self.assertEqual(expected_url["threat_level"], response_data["threat_level"], f"URL: {url}")
                self.assertEqual(expected_url["source"], response_data["source"], f"URL: {url}")

                self.assertIsNotNone(response_data.get("threat_categories"),
                                     f"Expected threat_categories to be None for URL: {url}")
                self.assertIsNotNone(response_data.get("site_categories"),
                                     f"Expected site_categories to be None for URL: {url}")
