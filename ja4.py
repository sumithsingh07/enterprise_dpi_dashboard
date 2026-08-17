"""
ja4.py

JA4 Fingerprint Generator
"""

import hashlib


class JA4Result:

    def __init__(self):
        self.valid = False
        self.ja4 = ""


class JA4Parser:

    @staticmethod
    def fingerprint(
        client_hello,
        sni_present=False,
        alpn=""
    ):

        if client_hello is None:
            return None

        # --------------------------------------------------
        # Safely read ClientHello fields
        # --------------------------------------------------

        if not isinstance(client_hello, dict):
            return None

        version = client_hello.get("version", 0)

        # --------------------------------------------------
        # TLS version
        # --------------------------------------------------

        version_str = {
            0x0301: "10",   # TLS 1.0
            0x0302: "11",   # TLS 1.1
            0x0303: "12",   # TLS 1.2
            0x0304: "13",   # TLS 1.3
        }.get(version)

        # Unknown/unsupported version.
        # Do not print anything during large PCAP analysis.
        if version_str is None:
            return None

        # --------------------------------------------------
        # Cipher suites
        # --------------------------------------------------

        cipher_suites = client_hello.get(
            "cipher_suites",
            []
        )

        if not isinstance(cipher_suites, (list, tuple)):
            cipher_suites = []

        # --------------------------------------------------
        # Extensions
        # --------------------------------------------------

        extensions = client_hello.get(
            "extensions",
            []
        )

        if not isinstance(extensions, (list, tuple)):
            extensions = []

        # --------------------------------------------------
        # Supported groups
        # --------------------------------------------------

        supported_groups = client_hello.get(
            "supported_groups",
            []
        )

        if not isinstance(
            supported_groups,
            (list, tuple)
        ):
            supported_groups = []

        # --------------------------------------------------
        # Signature algorithms
        # --------------------------------------------------

        signature_algorithms = client_hello.get(
            "signature_algorithms",
            []
        )

        if not isinstance(
            signature_algorithms,
            (list, tuple)
        ):
            signature_algorithms = []

        # --------------------------------------------------
        # Counts
        # --------------------------------------------------

        cipher_count = len(cipher_suites)

        extension_count = len(extensions)

        group_count = len(supported_groups)

        signature_count = len(
            signature_algorithms
        )

        # --------------------------------------------------
        # Transport
        # --------------------------------------------------

        transport = "t"

        # --------------------------------------------------
        # SNI
        # --------------------------------------------------

        sni = "d" if sni_present else "i"

        # --------------------------------------------------
        # ALPN
        # --------------------------------------------------

        alpn_value = alpn if alpn else "na"

        # --------------------------------------------------
        # JA4 header
        # --------------------------------------------------

        header = (
            f"{transport}"
            f"{version_str}"
            f"{sni}"
            f"{cipher_count:02d}"
            f"{extension_count:02d}"
            f"{group_count:02d}"
            f"{signature_count:02d}"
            f"{alpn_value}"
        )

        # --------------------------------------------------
        # Variable portion
        # --------------------------------------------------

        variable = (
            str(cipher_suites)
            + str(extensions)
            + str(supported_groups)
            + str(signature_algorithms)
        )

        digest = hashlib.sha256(
            variable.encode("utf-8")
        ).hexdigest()[:16]

        # --------------------------------------------------
        # Result
        # --------------------------------------------------

        result = JA4Result()

        result.valid = True

        result.ja4 = (
            f"{header}_{digest}"
        )

        return result