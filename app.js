# /etc/hostapd/hostapd.conf
# Managed by pi-gateway — edits here are overwritten by the web UI

interface=wlan0
driver=nl80211

# SSID — change via web UI or edit here
ssid=Pi-Gateway

# 802.11n on 2.4 GHz, channel 6
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1

# WPA2
wpa=2
wpa_passphrase=ChangeMe123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP

# Country code — change to your ISO 3166-1 alpha-2 country
country_code=DE
