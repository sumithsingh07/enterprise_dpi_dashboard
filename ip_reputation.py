"""
ip_reputation.py

Enterprise IP Reputation Engine
"""

import ipaddress


class ReputationResult:

    def __init__(self):

        self.malicious = False

        self.category = "Unknown"

        self.score = 0


class IPReputation:

    def __init__(self):

        self.database = {

            # TOR Exit Nodes
            "185.220.101.1": ("TOR Exit Node", 95),
            "185.220.101.2": ("TOR Exit Node", 95),

            # Malware C2
            "45.95.169.12": ("Malware C2", 100),

            # Test Examples
            "8.8.8.8": ("Google DNS", 0),
            "1.1.1.1": ("Cloudflare DNS", 0),
        }

    # ------------------------------------

    def lookup(self, ip):

        result = ReputationResult()

        try:

            addr = ipaddress.ip_address(ip)

            if addr.is_private:

                result.category = "Private Network"

                return result

            if ip in self.database:

                result.category = self.database[ip][0]

                result.score = self.database[ip][1]

                if result.score >= 80:

                    result.malicious = True

        except Exception:

            pass

        return result