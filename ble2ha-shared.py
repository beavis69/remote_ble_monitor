import asyncio
import sys
import os
import struct
import socket
import requests
import time
import configparser
import uuid
from bleak import BleakScanner
from bleak.args.bluez import BlueZScannerArgs

# --- PATHS ---
CONFIG_FILE = "/home/pi/ble2ha/config.ini"
WHITELIST_FILE = "/home/pi/ble2ha/whitelist.txt"
# -------------

HA_URL = ""
HEADERS = {}
HCI_DEV = 1
GATEWAY_ID = ""
LOG_INTERVAL = 30

DEBUG_LOCAL = False
TARGET_DEBUG_MAC = ""

whitelist_macs = set()
frame_counter = 0
last_log_time = time.time()
toggle_event_type = 0x00

http_queue = asyncio.Queue()

def load_configuration():
    """Reads all execution and debugging baselines directly from the config.ini file."""
    global HA_URL, HEADERS, HCI_DEV, GATEWAY_ID, LOG_INTERVAL, DEBUG_LOCAL, TARGET_DEBUG_MAC
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
        
        if config.has_section("DEBUG"):
            DEBUG_LOCAL = config.getboolean("DEBUG", "debug_local", fallback=False)
            TARGET_DEBUG_MAC = config.get("DEBUG", "target_debug_mac", fallback="").strip().replace(":", "").upper()
        
        HA_URL = f"http://{ha_ip}:{ha_port}/api/services/ble_monitor/parse_data"
        HEADERS = {"Authorization": f"Bearer {ha_token}", "content-type": "application/json"}
        
        if DEBUG_LOCAL:
            print(f"[Info] Configuration successfully loaded from {CONFIG_FILE}.", flush=True)
            print(f"[Info] Debug Active for MAC: {TARGET_DEBUG_MAC}", flush=True)
    except Exception as e:
        print(f"[Critical] Failed to parse configuration file: {e}", flush=True)
        sys.exit(1)

def load_whitelist():
    """Loads target MAC addresses into a text-based set for high-speed matching."""
    global whitelist_macs
    whitelist_macs = set()
    if not os.path.exists(WHITELIST_FILE):
        return
    try:
        with open(WHITELIST_FILE, "r") as f:
            for line in f:
                clean_mac = line.strip().replace(":", "").upper()
                if len(clean_mac) == 12:
                    formatted_mac = ":".join(clean_mac[i:i+2] for i in range(0, 12, 2))
                    whitelist_macs.add(formatted_mac)
        if DEBUG_LOCAL:
            print(f"[Info] Whitelist loaded successfully: {len(whitelist_macs)} devices monitored.", flush=True)
    except Exception as e:
        print(f"[Error] Failed to load whitelist file: {e}", flush=True)

async def http_sender_worker():
    global frame_counter, last_log_time
    session = requests.Session()
    session.headers.update(HEADERS)
    while True:
        packet_bytes = await http_queue.get()
        payload = {"packet": packet_bytes.hex(), "gateway_id": GATEWAY_ID}
        try:
            response = session.post(HA_URL, json=payload, timeout=0.5)
            if response.status_code == 200:
                frame_counter += 1
                http_queue.task_done()
            else:
                http_queue.task_done()
                await asyncio.sleep(1.0)
        except Exception:
            http_queue.task_done()
            await asyncio.sleep(1.0)

        current_time = time.time()
        if current_time - last_log_time >= LOG_INTERVAL:
            print(f"[Info] Sent {frame_counter} hci frames successfully over the last {LOG_INTERVAL}s. Backlog size: {http_queue.qsize()}", flush=True)
            frame_counter = 0
            last_log_time = current_time

def push_to_gateway(mac_upper, raw_payload, rssi):
    """Assembles the final hci frame with exact structural layout compliance."""
    global loop, toggle_event_type
    try:
        mac_raw = bytes.fromhex(mac_upper.replace(":", ""))
        rssi_byte = struct.pack("<B", rssi + 256 if rssi < 0 else rssi)
        
        toggle_event_type = 0x02 if toggle_event_type == 0x00 else 0x00
        hci_adv_headers = struct.pack("<BBBB", 0x02, 0x01, toggle_event_type, 0x00)
        
        total_len_byte = struct.pack("<B", len(raw_payload) + 12)
        data_len_byte = struct.pack("<B", len(raw_payload))
        
        fake_packet = (
            b'\x04\x3e' + 
            total_len_byte + 
            hci_adv_headers + 
            mac_raw[::-1] + 
            data_len_byte + 
            raw_payload + 
            rssi_byte
        )
        
        if DEBUG_LOCAL and mac_upper.replace(":", "").upper() == TARGET_DEBUG_MAC:
            print(f"[Debug] {mac_upper} | {len(fake_packet)}b | hci;{fake_packet.hex()}", flush=True)
        
        if http_queue.qsize() >= 1000:
            try:
                http_queue.get_nowait()
                http_queue.task_done()
            except asyncio.QueueEmpty:
                pass
        loop.call_soon_threadsafe(http_queue.put_nowait, fake_packet)
    except Exception:
        pass

def detection_callback(device, advertisement_data):
    mac_upper = device.address.upper()
    if mac_upper in whitelist_macs or len(whitelist_macs) == 0:
        try:
            xiaomi_processed = False
            
            # 1. PROCESS STRICTLY XIAOMI SERVICE DATA (0xFE95 - Température / Humidité)
            for s_uuid, data in advertisement_data.service_data.items():
                uuid_hex = s_uuid.hex if isinstance(s_uuid, uuid.UUID) else str(s_uuid).replace("-", "").lower()
                
                if "fe95" in uuid_hex or uuid_hex.endswith("00001000800000805f9b34fb"):
                    if len(data) >= 5:
                        ad_len = len(data) + 3
                        single_element = b'\x02\x01\x06' + struct.pack("<BB", ad_len, 0x16) + b'\x95\xfe' + data
                        push_to_gateway(mac_upper, single_element, advertisement_data.rssi)
                    xiaomi_processed = True
                    break

            # 2. PROCESS MANUFACTURER DATA (Active Scan Response Battery packets)
            for company_id, data in advertisement_data.manufacturer_data.items():
                # FIXED INDEXES: Checking explicit offsets inside the bytes array properly
                if company_id == 0x038F and len(data) >= 7 and data[0] == 0x25 and data[1] == 0x42:
                    ad_len = len(data) + 3
                    single_element = b'\x02\x01\x06' + struct.pack("<BB", ad_len, 0x16) + b'\x95\xfe' + data
                    push_to_gateway(mac_upper, single_element, advertisement_data.rssi)
                else:
                    if not xiaomi_processed:
                        company_bytes = struct.pack("<H", company_id)
                        single_element = b'\x02\x01\x06' + struct.pack("<BB", len(data) + 3, 0xFF) + company_bytes + data
                        push_to_gateway(mac_upper, single_element, advertisement_data.rssi)
        except Exception:
            pass

async def cache_cleaner_task():
    while True:
        os.system("sudo bluetoothctl remove * > /dev/null 2>&1")
        await asyncio.sleep(5.0)

async def main():
    global loop
    loop = asyncio.get_running_loop()
    load_configuration()
    load_whitelist()

    os.system("sudo killall -9 hcitool lescan hcidump bluetoothctl python3 2>/dev/null")
    os.system(f"sudo hciconfig hci{HCI_DEV} up")
    await asyncio.sleep(0.5)

    asyncio.create_task(http_sender_worker())
    asyncio.create_task(cache_cleaner_task())
    
    scanner = BleakScanner(
        detection_callback,
        bluez=BlueZScannerArgs(adapter=f"hci{HCI_DEV}"),
        scanning_mode="active"
    )
    
    try:
        await scanner.start()
        while True:
            await asyncio.sleep(3600)
    except Exception:
        pass
    finally:
        await scanner.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown request processed.", flush=True)

