import asyncio
import json
import logging
import os
import random
import re
import tempfile
import zipfile

import requests


class URLManagerWithURLHaus:
    def __init__(self, abuse_zip_url="https://urlhaus.abuse.ch/downloads/json/"):
        self.enabled = False
        self.url_set = set()
        self.url_info_dict = {}
        self.abuse_zip_url = abuse_zip_url
        if self.update_url_set():
            self.enabled = True

    def download_and_check_url_file(self, url_file_url, local_file_path):
        try:
            response = requests.get(url_file_url)
            if response.status_code == 200:
                with open(local_file_path, "w") as f:
                    f.write(response.text)
                return True
        except requests.exceptions.RequestException:
            return False
        return False

    def download_and_unzip_file(self, extract_to='.'):
        """
        Downloads a ZIP file from a specified URL and extracts its contents to a given directory.

        Parameters:
        - url (str): The URL of the ZIP file to download.
        - extract_to (str): The directory path where the contents of the ZIP file will be extracted. Defaults to the current directory.

        Returns:
        - bool: True if the file was successfully downloaded and extracted, False otherwise.
        """
        try:
            r = requests.get(self.abuse_zip_url)
            r.raise_for_status()  # Raise an error for bad responses

            # Use a temporary file instead of a fixed file path
            with tempfile.TemporaryFile() as tmp:
                tmp.write(r.content)
                tmp.seek(0)  # Move the cursor to the start of the file

                with zipfile.ZipFile(tmp, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)

            return True
        except Exception as e:
            print(f"Failed to download and unzip file: {e}")
            return False

    def process_json_file(self, file_path):
        """
         Processes a JSON file containing URL entries, extracting and storing domain names from each URL.

         Parameters:
         - file_path (str): The file path to the JSON file to be processed.

         Returns:
         - bool: True if the file was successfully processed, False otherwise.
         """
        pattern = r'https?://([^/:]+)'
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
                # Iterate over each unique identifier in the JSON data
                for id, entries in data.items():
                    # Each 'entries' is a list of URL entries
                    for entry in entries:
                        url = entry.get('url', '')
                        match = re.search(pattern, url)
                        if match:
                            location = match.group(1)
                            # Remove port if present
                            location = re.sub(r':\d+', '', location)
                            entry_info = entry.copy()
                            # self.url_set.add(location)
                            # Store the entry info in the dictionary using the URL as key
                            self.url_info_dict[location] = entry_info

            return True
        except Exception as e:
            print(f"Failed to process JSON file: {e}")
            return False

    def update_url_set(self):
        """
        Updates the set of URLs by downloading a ZIP file containing a JSON file with URL entries, extracting it,
        and processing the JSON file to extract URLs.

        Returns:
        - bool: True if the URL set was successfully updated, False otherwise.
        """
        json_file_name = "urlhaus_full.json"  # The specific JSON file to process

        # Use a context manager to create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Attempt to download and unzip the file into the temporary directory
            if self.download_and_unzip_file(temp_dir):
                json_file_path = os.path.join(temp_dir, json_file_name)
                if os.path.exists(json_file_path):
                    if self.process_json_file(json_file_path):
                        return True
                    else:
                        print("Failed to process the JSON file")
                        return False
                else:
                    print("JSON file not found in the extracted contents")
                    return False
            else:
                print("Failed to download and unzip the abuse list")
                return False

    async def try_update_url_set_with_retries(self, retries=3, delay=5):
        """
        Attempts to update the URL set, retrying on failure.

        Parameters:
        - retries (int): Number of times to retry the update.
        - delay (int): Delay between retries in seconds.

        Returns:
        - None
        """
        while True:
            attempt = 0
            while attempt < retries:
                try:
                    if self.update_url_set():
                        logging.info("URL list updated successfully.")
                        self.enabled = True
                        break
                    else:
                        raise IOError("Failed to update abuse URL list")
                except Exception as e:
                    attempt += 1
                    logging.error(f"Attempt {attempt} failed to update URL list: {e}")
                    if attempt < retries:
                        logging.info(f"Retrying in {delay} seconds...")
                        await asyncio.sleep(delay)
                    else:
                        logging.error("All attempts to update the URL list have failed.")
                        break
            await asyncio.sleep(24 * 60 * 60)  # 1 day


    def check_url(self, url):
        return self.url_info_dict.get(url, {})

    def add_url(self, url):
        self.url_info_dict[url] = {"url": url, "url_status": "online"}

    def get_random_urls(self, max_urls: int = 10):
        urls = list(self.url_info_dict.keys())  # or list(url_dict.values()) if URLs are values
        random_urls = random.sample(urls, min(len(urls), max_urls))  # Ensure not to exceed the list size
        return random_urls

