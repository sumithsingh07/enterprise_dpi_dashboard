"""
geoip.py

Enterprise GeoIP + ASN Lookup
"""

import ipaddress
import maxminddb


class GeoIP:

    def __init__(self):

        self.city_db = maxminddb.open_database(
            "database/GeoLite2-City.mmdb"
        )

        self.asn_db = maxminddb.open_database(
            "database/GeoLite2-ASN.mmdb"
        )

    # ----------------------------------------

    def lookup(self, ip):

        result = {

            "country": "Unknown",

            "city": "",

            "asn": "",

            "organization": ""
        }

        try:

            addr = ipaddress.ip_address(ip)

            if addr.is_private:

                result["country"] = "Private Network"

                return result

            city = self.city_db.get(ip)

            if city:

                if "country" in city:

                    result["country"] = city["country"]["names"]["en"]

                if "city" in city:

                    result["city"] = city["city"]["names"]["en"]

            asn = self.asn_db.get(ip)

            if asn:

                result["asn"] = str(asn.get("autonomous_system_number", ""))

                result["organization"] = asn.get(
                    "autonomous_system_organization",
                    ""
                )

        except Exception:

            pass

        return result

    # ----------------------------------------

    def close(self):

        self.city_db.close()

        self.asn_db.close()