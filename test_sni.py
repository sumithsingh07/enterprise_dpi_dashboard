from scapy.all import rdpcap

from sni_extractor import ApplicationClassifier

packets = rdpcap("sample.pcapng")

for packet in packets:

    result = ApplicationClassifier.classify(packet)

    if result:

        app, sni = result

        print("--------------------------------")

        print("SNI :", sni)

        print("Application :", app.name)