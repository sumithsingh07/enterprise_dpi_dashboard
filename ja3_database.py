"""
ja3_database.py

JA3 Fingerprint Database

Maps JA3 hashes to applications.
"""

from dpi_types import AppType


class JA3Database:

    DATABASE = {

        # -----------------------------
        # Google Chrome (Example)
        # -----------------------------
        "e7d705a3286e19ea42f587b344ee6865":
            AppType.GOOGLE,

        # -----------------------------
        # Microsoft Edge
        # -----------------------------
        "72a589da586844d7f0818ce684948eea":
            AppType.MICROSOFT,

        # -----------------------------
        # Firefox
        # -----------------------------
        "b20b44b18b853ef29ab773e921b03422":
            AppType.UNKNOWN,

        # -----------------------------
        # AnyDesk
        # -----------------------------
        "9d1f7b6f3df0ef9d4f31d01d66f3fb43":
            AppType.ANYDESK,

        # -----------------------------
        # Zoom
        # -----------------------------
        "4d7a28d6f2263ed61de88ca66eb011e3":
            AppType.ZOOM,

        # -----------------------------
        # WhatsApp Desktop
        # -----------------------------
        "c7a3d7db8fbcae84f2f3cf1911091cf1":
            AppType.WHATSAPP,

        # -----------------------------
        # GitHub Desktop
        # -----------------------------
        "2b8f63d08a42d4d9ab7b0f9a14be4628":
            AppType.GITHUB,
    }

    @staticmethod
    def lookup(hash_value):

        return JA3Database.DATABASE.get(
            hash_value,
            AppType.UNKNOWN
        )