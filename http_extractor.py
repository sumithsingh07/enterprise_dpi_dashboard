"""
http_extractor.py

HTTP File Extractor

Extracts HTTP response bodies and saves them to disk.
"""

import os
from datetime import datetime


class HTTPFileExtractor:

    def __init__(self):

        self.output_dir = "downloads"

        os.makedirs(self.output_dir, exist_ok=True)

        self.saved_files = 0

    def save(self, http_response):

        if not hasattr(http_response, "body"):
            return

        if not http_response.body:
            return

        filename = self.make_filename(http_response)

        path = os.path.join(
            self.output_dir,
            filename
        )

        with open(path, "wb") as f:
            if isinstance(http_response.body, str):
                f.write(http_response.body.encode("utf-8"))
            else:
                f.write(http_response.body)
        self.saved_files += 1

        print(f"\nSaved File : {path}")

    def make_filename(self, response):

        extension = ".bin"

        if hasattr(response, "content_type"):

            c = response.content_type.lower()

            if "html" in c:
                extension = ".html"

            elif "jpeg" in c:
                extension = ".jpg"

            elif "png" in c:
                extension = ".png"

            elif "gif" in c:
                extension = ".gif"

            elif "pdf" in c:
                extension = ".pdf"

            elif "zip" in c:
                extension = ".zip"

            elif "json" in c:
                extension = ".json"

            elif "xml" in c:
                extension = ".xml"

            elif "javascript" in c:
                extension = ".js"

            elif "css" in c:
                extension = ".css"

            elif "exe" in c:
                extension = ".exe"

        return datetime.now().strftime("%Y%m%d_%H%M%S_%f") + extension

    def print_statistics(self):

        print("\n========== HTTP FILES ==========")

        print("Extracted :", self.saved_files)

        print("===============================")
