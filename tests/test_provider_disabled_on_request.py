import unittest

from prompt_guardian.server import prompt_guardian_app, startup_event
from fastapi.testclient import TestClient


class TestURLs(unittest.IsolatedAsyncioTestCase):

    async def test_disable_all_providers(self):
        prompt = "hello world"
        # Add URL to the list

        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            state = client.app.state
            # state.url_manager.enabled = False
            response = client.post("/check-prompt"
                                   , json={"text": prompt,
                                           "extractedUrls": [],
                                           "check_openai": False,
                                           "check_gemini": False,
                                           "check_azure": False,
                                           "check_threats": False,
                                           "check_url": False
                                           })
            self.assertEqual(response.status_code, 200)
            expected_url_verdict = [{'site_categories': None, 'source': 'System', 'target': 'Prompt check for malware '
                                                                                            'URLs is disabled per '
                                                                                            'client request',
                                     'threat_categories': None, 'threat_level': 'unknown'}]
            expected = {'prompt_injection': {'azure': 'Prompt injection detection with Azure is disabled per client '
                                                      'request', 'gemini': 'Prompt injection detection with Gemini is '
                                                                           'disabled per client request',
                                             'openai': 'Prompt injection detection with OpenAI is disabled per client '
                                                       'request'}, 'url_verdict': expected_url_verdict,
                        'threats': "Prompt check for DLP is disabled per client request"}
            self.assertEqual(expected, response.json())

    async def test_only_threats(self):
        prompt = "hello world"
        # Add URL to the list

        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            response = client.post("/check-prompt"
                                   , json={"text": prompt,
                                           "extractedUrls": [],
                                           "check_openai": False,
                                           "check_gemini": False,
                                           "check_azure": False,
                                           "check_threats": True,
                                           "check_url": False
                                           })
            self.assertEqual(response.status_code, 200)
            self.assertEqual('No Threats Detected', response.json().get("threats"))

    async def test_url_disabled(self):
        prompt = "http://malicious.url"
        # Add URL to the list

        # Test the URL
        with TestClient(prompt_guardian_app) as client:
            response = client.post("/check-prompt"
                                   , json={"text": prompt,
                                           "extractedUrls": [],
                                           "check_openai": False,
                                           "check_gemini": False,
                                           "check_azure": False,
                                           "check_threats": True,
                                           "check_url": False
                                           })
            self.assertEqual(response.status_code, 200)
            expected = {'site_categories': None, 'source': 'System', 'target': 'Prompt check for malware URLs is '
                                                                               'disabled per client request',
                        'threat_categories': None, 'threat_level': 'unknown'}

            actual = response.json().get("url_verdict")[0]
            self.assertEqual(expected, actual)
