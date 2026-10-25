import asyncio
import sys
import os
import struct
import socket
import requests
import ctypes
import time
import configparser
import aioblescan as aiobs

# --- PATHS ---
CONFIG_FILE = "/home/pi/ble2ha/config.ini"
WHITELIST_FILE = "/home/pi/ble2ha/whitelist.txt"
# -------------

HA_URL = ""
HEADERS = {}
HCI_DEV = 1
GATEWAY_ID = ""
LOG_INTERVAL = 30

AF_BLUETOOTH = 31
BTPROTO_HCI = 1

libc = ctypes.CDLL(None)
whitelist_binaries = []

# Global variables for tracking metrics and performance
frame_counter = 0
last_log_time = time.time()

# Asynchronous queue to process HTTP requests out-of-band
http_queue = asyncio.Queue()

def load_configuration():
    """Reads configuration directly from the external config.ini file."""
    global HA_URL, HEADERS, HCI_DEV, GATEWAY_ID, LOG_INTERVAL
    if not os.path.exists(CONFIG_FILE):
        print(f"[Critical] Configuration file {CONFIG_FILE} not found. Exiting.", flush=True)
        sys.exit(1)
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        ha_ip = config.get("HOME_ASSISTANT", "ha_ip")
        ha_port = config.get("HOME_ASSISTANT", "ha_port")
        ha_token = config.get("HOME_ASSISTANT", "ha_token").strip('"')
        HCI_DEV = config.getint("HARDWARE", "hci_dev")
        GATEWAY_ID = config.get("HARDWARE", "gateway_id").strip('"')
        LOG_INTERVAL = config.getint("LOGS", "log_interval")
        HA_URL = f"http://{ha_ip}:{ha_port}/api/services/ble_monitor/parse_data"
        HEADERS = {"Authorization": f"Bearer {ha_token}", "content-type": "application/json"}
        print(f"[Info] Configuration successfully loaded from {CONFIG_FILE}.", flush=True)
    except Exception as e:
        print(f"[Critical] Failed to parse configuration file: {e}", flush=True)
        sys.exit(1)

def load_whitelist():
    """Loads target MAC addresses and pre-computes their Little-Endian binary signatures."""
    global whitelist_binaries
    whitelist_binaries = []
    if not os.path.exists(WHITELIST_FILE):
        print(f"[Warning] Whitelist file {WHITELIST_FILE} not found. Running in OPEN mode.", flush=True)
        return
    try:
        with open(WHITELIST_FILE, "r") as f:
            for line in f:
                clean_mac = line.strip().replace(":", "").lower()
                if len(clean_mac) == 12:
                    mac_bytes = bytes.fromhex(clean_mac)
                    mac_reversed = mac_bytes[::-1]
                    whitelist_binaries.append((clean_mac, mac_reversed))
        print(f"[Info] Whitelist loaded successfully: {len(whitelist_binaries)} devices monitored.", flush=True)
    except Exception as e:
        print(f"[Error] Failed to load whitelist file: {e}", flush=True)

async def http_sender_worker():
    """Asynchronous worker that continuously flushes the queue to Home Assistant."""
    global frame_counter, last_log_time
    session = requests.Session()
    session.headers.update(HEADERS)
    while True:
        packet_bytes = await http_queue.get()
        payload = {"packet": packet_bytes.hex(), "gateway_id": GATEWAY_ID}
        success = False
        try:
            response = session.post(HA_URL, json=payload, timeout=0.5)
            if response.status_code == 200:
                frame_counter += 1
                success = True
        except Exception:
            pass
        if success:
            http_queue.task_done()
        else:
            if http_queue.qsize() < 1000:
                await http_queue.put(packet_bytes)
            http_queue.task_done()
            await asyncio.sleep(2.0)
        current_time = time.time()
        if current_time - last_log_time >= LOG_INTERVAL:
            print(f"[Stats] Sent {frame_counter} frames successfully over the last {LOG_INTERVAL}s. Backlog size: {http_queue.qsize()}", flush=True)
            frame_counter = 0
            last_log_time = current_time

def read_socket_callback(mysocket):
    """Triggered instantly by the event loop when raw bytes are ready in the kernel buffer."""
    try:
        data = mysocket.recv(4096)
        if data and len(data) > 0:
            for clean_mac, mac_reversed in whitelist_binaries:
                if mac_reversed in data:
                    current_size = http_queue.qsize()
                    if current_size >= 1000:
                        try:
                            http_queue.get_nowait()
                            http_queue.task_done()
                        except asyncio.QueueEmpty:
                            pass
                    loop.call_soon_threadsafe(http_queue.put_nowait, data)
                    break
    except BlockingIOError:
        pass
    except Exception:
        pass

async def main():
    global loop
    loop = asyncio.get_running_loop()
    load_configuration()
    load_whitelist()

    print(f"Preparing hardware interface hci{HCI_DEV}...", flush=True)
    # Stop legacy scan engine and bring down the interface to trigger clean binding
    os.system("sudo killall -9 hcitool lescan hcidump bluetoothctl python3 2>/dev/null")
    os.system(f"sudo hciconfig hci{HCI_DEV} down")
    await asyncio.sleep(0.5)

    print(f"Opening exclusive HCI_CHANNEL_USER socket via aioblescan on hci{HCI_DEV}...", flush=True)
    try:
        # Use aioblescan master hook to request the exclusive bound hardware descriptor
        mysocket = aiobs.create_bt_socket(HCI_DEV)
        mysocket.setblocking(False)
    except Exception as e:
        print(f"Critical error initializing aioblescan socket: {e}", flush=True)
        sys.exit(1)

    print("Triggering hardware passive scanning via system daemon tools...", flush=True)
    # Executing hardware triggers via standard tools to avoid Python 3.13 library variance crashes
    os.system(f"sudo hciconfig hci{HCI_DEV} up")
    os.system(f"sudo hcitool -i hci{HCI_DEV} lescan --passive --duplicates > /dev/null 2>&1 &")
    await asyncio.sleep(0.5)

    # Start the background flushing task
    asyncio.create_task(http_sender_worker())

    # Monitor the file descriptor directly inside the event loop using native add_reader
    loop.add_reader(mysocket.fileno(), read_socket_callback, mysocket)
    print(f"High-velocity exclusive packet stream listening via event loop reader. Reporting every {LOG_INTERVAL}s...", flush=True)
    
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown request processed. Safely closing aioblescan resources.", flush=True)

