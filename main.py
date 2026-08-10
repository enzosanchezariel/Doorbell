from scapy.all import AsyncSniffer, ARP
from ping3 import ping
import threading
import time
import os
import subprocess
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
SYSTEM_NOTIFICATIONS = os.getenv("SYSTEM_NOTIFICATIONS", "false").lower() == "true"
TELEGRAM_NOTIFICATIONS = os.getenv("TELEGRAM_NOTIFICATIONS", "false").lower() == "true"

CHECKING_WHOS_HOME = False
QUEUED_ARPS = []

if SYSTEM_NOTIFICATIONS:
    from plyer import notification
if TELEGRAM_NOTIFICATIONS:
    import requests

def get_by_mac(pkt):
    for target in TARGETS:
        for mac in target["macs"]:
            if pkt.hwsrc.lower() == mac:
                return target
    return None

def check_whos_home():
    global CHECKING_WHOS_HOME
    global QUEUED_ARPS

    CHECKING_WHOS_HOME = True
    clear()
    print("STARTING PERIODICAL LAN SCAN")
    for target in TARGETS:
        print("Scanning "+target["name"]+"...")
        successful_ping = False
        for ip in target["ips"]:
            if not successful_ping:
                strikes = 0
                while strikes < 3 and not successful_ping:
                    try:
                        delay = ping(ip, timeout=2)
                        if delay is not None and delay is not False:
                            successful_ping = True
                    except:
                        pass
                    strikes += 1
                    time.sleep(1)
        if successful_ping: target["present"] = True
        else: target["present"] = False
    clear()
    for target in TARGETS:
        print(target["name"] + ": " + ("yes" if target["present"] else "no"))
    CHECKING_WHOS_HOME = False
    for queued in QUEUED_ARPS:
        trigger_arrival(queued)
    QUEUED_ARPS = []

def trigger_arrival(target):
    global CHECKING_WHOS_HOME
    global QUEUED_ARPS

    if not CHECKING_WHOS_HOME:
        target["present"] = True
        message = target["name"] + " has arrived home."

        if SYSTEM_NOTIFICATIONS:
            notification.notify(
                title='Someone arrived',
                message=message,
                timeout=5
            )

        if TELEGRAM_NOTIFICATIONS:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
            payload = {
                "chat_id": CHAT_ID,
                "text": message
            }

            response = requests.post(url, json=payload)
    else:
        if target not in QUEUED_ARPS:
            print("Queued a target")
            QUEUED_ARPS.append(target)


def packet_callback(pkt):
    if ARP in pkt:
        foundByMac = get_by_mac(pkt)
        if foundByMac:
            if not foundByMac["present"]:
                trigger_arrival(foundByMac)

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