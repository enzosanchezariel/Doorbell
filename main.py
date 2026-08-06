from scapy.all import AsyncSniffer, ARP
from ping3 import ping
import threading
import time
import os
import subprocess
from plyer import notification
import requests
from dotenv import load_dotenv
import json

def clear():
    subprocess.run(
        ["cls"] if os.name == "nt" else ["clear"],
        shell=(os.name == "nt")
    )

load_dotenv()

TARGETS = []
with open("targets.json", "r") as file:
    TARGETS = json.load(file)

for target in TARGETS:
    target["present"] = False

CHECK_DELAY = int(os.getenv("CHECK_DELAY")) * 60
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

def get_by_mac(pkt):
    for target in TARGETS:
        for mac in target["macs"]:
            if pkt.hwsrc.lower() == mac:
                return target
    return None

def check_whos_home():
    clear()
    for target in TARGETS:
        target["present"] = False
    for target in TARGETS:
        for ip in target["ips"]:
            try:
                delay = ping(ip, timeout=2)
                if delay is not None and delay is not False:
                    target["present"] = True
            except:
                pass
    for target in TARGETS:
        print(target["name"] + ": " + ("yes" if target["present"] else "no"))

def trigger_arrival(target):
    message = target["name"] + " has arrived home."

    notification.notify(
        title='Someone arrived',
        message=message,
        timeout=5
    )

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message
    }

    response = requests.post(url, json=payload)


def packet_callback(pkt):
    if ARP in pkt:
        foundByMac = get_by_mac(pkt)
        if foundByMac:
            if not foundByMac["present"]:
                trigger_arrival(foundByMac)
                check_whos_home()

def check_whos_home_thread():
    while True:
        check_whos_home()
        time.sleep(CHECK_DELAY)

thread = threading.Thread(target=check_whos_home_thread, daemon=True)
thread.start()

try:
    sniffer = AsyncSniffer(filter="arp", prn=packet_callback, store=False)
    sniffer.start()
    sniffer.join()
except KeyboardInterrupt:
    print("\nCerrando...")
    sniffer.stop()