import asyncio
import logging

import requests


class URLListManager:
    def __init__(self):
        self.url_set = set()
        self.update_url_set()

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

    def update_url_set(self):
        abuse_list_url = "https://urlhaus.abuse.ch/downloads/text_online/"  # URL of the abuse list
        local_file_path = "abuse_list.txt"

        if self.download_and_check_url_file(abuse_list_url, local_file_path):
            with open(local_file_path, "r") as file:
                self.url_set = file.read().strip().split('\n')
        else:
            raise Exception("Failed to download the abuse list")

    async def periodic_update_url_list(self):
        while True:
            try:
                self.update_url_set()
                logging.info("URL list updated successfully.")
            except Exception as e:
                logging.error(f"Failed to update URL list: {e}")

            await asyncio.sleep(86400)

    def check_url(self, url):
        return url in self.url_set

    def add_url(self, url):
        self.url_set.add(url)
