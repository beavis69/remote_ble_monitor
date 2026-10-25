# remote_ble_monitor
Simple script to send bluetooth HCI packet to a Home Assistant ble_monitor intégration.
Used to extend range of ble_monitor using a computer (rpi zero 2w in my case) with a bluetooth adapter.

# 2 versions :
* ble2ha-shared.py : other programs can also use the hci adapter ( hci packets are faked as they are reconstructed )
* ble2ha-exclusive.py : access to hci device is exclusive and hci packet are genuine received packets.

# Links : 
* ble_monitor integration : https://github.com/custom-components/ble_monitor
* https://custom-components.github.io/ble_monitor/parse_data 
