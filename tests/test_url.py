import unittest
import pytest
import httpx
import pytest_asyncio

from prompt_guardian.server import prompt_guardian_app, startup_event


class TestFastAPIApp(unittest.TestCase):

    client = None

    @classmethod
    async def setUpClass(cls):
        cls.client = httpx.AsyncClient(app=prompt_guardian_app, base_url="http://test")

    @classmethod
    async def tearDownClass(cls):
        await cls.client.aclose()

    async def add_remove_url(self, url, add=True):
        if add:
            # Add the URL
            await self.client.post("/add-url", json={"url": url})
        else:
            # Remove the URL (if there's an endpoint for it)
            await self.client.post("/remove-url", json={"url": url})

    async def test_check_url_in_abuse_list(self):
        test_url = "http://example.com/malicious"
        # Add URL to the list
        await self.add_remove_url(test_url, add=True)

        # Test the URL
        response = await self.client.post("/check-prompt", json={"url": test_url})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"result": "URL is in the abuse list"})

        # Remove the URL from the list (optional)
        await self.add_remove_url(test_url, add=False)

    async def test_check_url_not_in_abuse_list(self):
        test_url = "http://example.com/safe"  # Replace with a URL not in your abuse list
        response = await self.client.post("/check-prompt", json={"url": test_url})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"result": "URL is not in the abuse list"})


@pytest.mark.asyncio
async def test_check_prompt_with_malware_url(async_client):
    # This test assumes that the URL 'http://malware.com' is recognized as malicious
    response = await async_client.post("/check-prompt",
                                       json={"text": "This is a test", "extractedUrls": ["http://malware.com"]})
    assert response.status_code == 200
    assert "Malware URL(s)" in response.json()["status"]


@pytest.mark.asyncio
async def test_check_prompt_without_malware_url(async_client):
    # This test assumes that the URL 'http://safe.com' is not recognized as malicious
    response = await async_client.post("/check-prompt", json={"text": "This is a test", "extractedUrls": ["http://safe.com"]})
    assert response.status_code == 200
    assert "No Malware URL(s)" in response.json()["status"]

# Add more tests to cover different scenarios, including prompt injection detection, etc.
