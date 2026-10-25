# remote_ble_monitor
Simple script to send bluetooth HCI packet to a Home Assistant ble_monitor intégration.
Used to extend range of ble_monitor using a computer (rpi zero 2w in my case) with a bluetooth adapter.

# 2 versions :
* ble2ha-shared.py : other programs can also use the hci adapter ( hci packets are faked as they are reconstructed )
* ble2ha-exclusive.py : access to hci device is exclusive and hci packet are genuine received packets.

# Links : 
* ble_monitor integration : https://github.com/custom-components/ble_monitor
* https://custom-components.github.io/ble_monitor/parse_data 

#### Disclaimer

**Use at your own risk.** This script interacts directly with system-level Bluetooth interfaces (HCI) and external home automation platforms (Home Assistant / BLE Monitor). 

* **No Warranty:** This software is provided "as is" without any warranties of any kind. The author assumes no responsibility for system instability, Bluetooth hardware crashes, or dropped packets.
* **Home Automation Impact:** Since this script forwards data to Home Assistant, any failure, delay, or bug in this code could result in inaccurate sensor readings or failed automations. Do not rely on this script for critical, safety-related, or medical monitoring.
* **Liability:** In no event shall the authors be liable for any claims, damages, or other liability arising from the use of this software.
