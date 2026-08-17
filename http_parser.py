"""
http_parser.py

Manual HTTP Parser

Parses HTTP Requests and Responses from TCP payloads.

Equivalent to the C++ HTTP parser.
"""

from dataclasses import dataclass


# ==========================================================
# HTTP Request
# ==========================================================

@dataclass
class HTTPRequest:

    method: str = ""

    uri: str = ""

    version: str = ""

    host: str = ""

    user_agent: str = ""

    content_type: str = ""

    content_length: int = 0

    headers: dict = None

    body: str = ""


# ==========================================================
# HTTP Response
# ==========================================================

@dataclass
class HTTPResponse:

    version: str = ""

    status_code: int = 0

    reason: str = ""

    content_type: str = ""

    content_length: int = 0

    headers: dict = None

    body: str = ""


# ==========================================================
# HTTP Parser
# ==========================================================

class HTTPParser:

    REQUEST_METHODS = (

        "GET",

        "POST",

        "PUT",

        "DELETE",

        "HEAD",

        "OPTIONS",

        "PATCH",

        "CONNECT",

        "TRACE"

    )

    # ------------------------------------------------------
    # Is HTTP Request?
    # ------------------------------------------------------

    @staticmethod
    def is_request(payload: bytes):

        try:

            text = payload.decode("utf-8", errors="ignore")

        except Exception:

            return False

        for method in HTTPParser.REQUEST_METHODS:

            if text.startswith(method + " "):

                return True

        return False


    # ------------------------------------------------------
    # Is HTTP Response?
    # ------------------------------------------------------

    @staticmethod
    def is_response(payload: bytes):

        try:

            text = payload.decode("utf-8", errors="ignore")

        except Exception:

            return False

        return text.startswith("HTTP/")


    # ------------------------------------------------------
    # Is HTTP?
    # ------------------------------------------------------

    @staticmethod
    def is_http(payload: bytes):

        return (

            HTTPParser.is_request(payload)

            or

            HTTPParser.is_response(payload)

        )
        # ------------------------------------------------------
    # Parse HTTP Request
    # ------------------------------------------------------

    @staticmethod
    def parse_request(payload: bytes):

        try:
            text = payload.decode(
                "utf-8",
                errors="ignore"
            )
        except Exception:
            return None

        lines = text.split("\r\n")

        if len(lines) == 0:
            return None

        request_line = lines[0].split()

        if len(request_line) != 3:
            return None

        request = HTTPRequest()

        request.method = request_line[0]
        request.uri = request_line[1]
        request.version = request_line[2]

        request.headers = {}

        body_start = False
        body_lines = []

        for line in lines[1:]:

            if body_start:
                body_lines.append(line)
                continue

            if line == "":
                body_start = True
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            request.headers[key.strip()] = value.strip()

        request.host = request.headers.get(
            "Host",
            ""
        )

        request.user_agent = request.headers.get(
            "User-Agent",
            ""
        )

        request.content_type = request.headers.get(
            "Content-Type",
            ""
        )

        try:
            request.content_length = int(
                request.headers.get(
                    "Content-Length",
                    "0"
                )
            )
        except ValueError:
            request.content_length = 0

        request.body = "\r\n".join(body_lines)

        return request


    # ------------------------------------------------------
    # Parse HTTP Response
    # ------------------------------------------------------

    @staticmethod
    def parse_response(payload: bytes):

        try:
            text = payload.decode(
                "utf-8",
                errors="ignore"
            )
        except Exception:
            return None

        lines = text.split("\r\n")

        if len(lines) == 0:
            return None

        status = lines[0].split(" ", 2)

        if len(status) < 3:
            return None

        response = HTTPResponse()

        response.version = status[0]

        try:
            response.status_code = int(status[1])
        except ValueError:
            response.status_code = 0

        response.reason = status[2]

        response.headers = {}

        body_start = False
        body_lines = []

        for line in lines[1:]:

            if body_start:
                body_lines.append(line)
                continue

            if line == "":
                body_start = True
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            response.headers[key.strip()] = value.strip()

        response.content_type = response.headers.get(
            "Content-Type",
            ""
        )

        try:
            response.content_length = int(
                response.headers.get(
                    "Content-Length",
                    "0"
                )
            )
        except ValueError:
            response.content_length = 0

        response.body = "\r\n".join(body_lines)

        return response


    # ------------------------------------------------------
    # Parse Any HTTP Packet
    # ------------------------------------------------------

    @staticmethod
    def parse(payload: bytes):

        if HTTPParser.is_request(payload):
            return HTTPParser.parse_request(payload)

        if HTTPParser.is_response(payload):
            return HTTPParser.parse_response(payload)

        return None
        # ------------------------------------------------------
    # Print HTTP Request
    # ------------------------------------------------------

    @staticmethod
    def print_request(request: HTTPRequest):

        print("\n========== HTTP REQUEST ==========")

        print("Method          :", request.method)
        print("URI             :", request.uri)
        print("Version         :", request.version)
        print("Host            :", request.host)
        print("User-Agent      :", request.user_agent)
        print("Content-Type    :", request.content_type)
        print("Content-Length  :", request.content_length)

        if request.headers:
            print("\nHeaders:")
            for key, value in request.headers.items():
                print(f"  {key}: {value}")

        if request.body:
            print("\nBody:")
            print(request.body[:200])

        print("==================================\n")


    # ------------------------------------------------------
    # Print HTTP Response
    # ------------------------------------------------------

    @staticmethod
    def print_response(response: HTTPResponse):

        print("\n========== HTTP RESPONSE ==========")

        print("Version         :", response.version)
        print("Status Code     :", response.status_code)
        print("Reason          :", response.reason)
        print("Content-Type    :", response.content_type)
        print("Content-Length  :", response.content_length)

        if response.headers:
            print("\nHeaders:")
            for key, value in response.headers.items():
                print(f"  {key}: {value}")

        if response.body:
            print("\nBody:")
            print(response.body[:200])

        print("===================================\n")


    # ------------------------------------------------------
    # Get Host
    # ------------------------------------------------------

    @staticmethod
    def get_host(payload: bytes):

        request = HTTPParser.parse_request(payload)

        if request is None:
            return ""

        return request.host


    # ------------------------------------------------------
    # Get User Agent
    # ------------------------------------------------------

    @staticmethod
    def get_user_agent(payload: bytes):

        request = HTTPParser.parse_request(payload)

        if request is None:
            return ""

        return request.user_agent


    # ------------------------------------------------------
    # Get URI
    # ------------------------------------------------------

    @staticmethod
    def get_uri(payload: bytes):

        request = HTTPParser.parse_request(payload)

        if request is None:
            return ""

        return request.uri