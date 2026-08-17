from scapy.all import sniff
from dpi_engine import DPIEngine
import traceback

engine = DPIEngine()

print("Starting live capture...")

def process(pkt):
    try:
        raw_packet = bytes(pkt)
        engine.process_packet(raw_packet)
    except Exception:
        traceback.print_exc()

sniff(prn=process, store=False,count=10)