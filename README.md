# blegotchi

A [pwnagotchi](https://github.com/jayofelern/pwnagotchi) plugin that scans for Bluetooth Low Energy (BLE) devices using Bettercap, with optional GPS tracking and WiGLE upload support.

Based on [xble](https://github.com/nickmccollum/xble) by nickmccollum, rewritten to mirror the architecture of pwnagotchi's built-in [wigle.py](https://github.com/jayofelern/pwnagotchi/blob/master/pwnagotchi/plugins/default/wigle.py) plugin.

## Features

- Scans for BLE devices using Bettercap's `ble.recon` module
- Stores discovered devices with name, manufacturer, and timestamps
- Optional GPS coordinates (if the `gps` plugin is loaded)
- Optional WiGLE upload (reuses the `wigle` plugin's API key config)
- Fun personality messages in auto mode, plain stats in manual mode
- Milestone celebrations at 10, 50, 100, 250, 500, and 1000 devices
- Webhook endpoint for accessing device data as JSON

## Installation

Copy `blegotchi.py` to your pwnagotchi's custom plugins directory:

```bash
scp blegotchi.py pi@<pwnagotchi-ip>:/usr/local/share/pwnagotchi/custom-plugins/
```

## Configuration

Add to `/etc/pwnagotchi/config.toml`:

```toml
main.plugins.blegotchi.enabled = true
main.plugins.blegotchi.timer = 45           # seconds between scans (default: 45)
main.plugins.blegotchi.bettercap_path = "/usr/local/bin/bettercap"  # default
main.plugins.blegotchi.position = [125, 62] # UI element position (default)
main.plugins.blegotchi.count_interval = 86400  # seconds before incrementing device count (default: 24h)
```

### GPS (optional)

If the `gps` plugin is enabled, blegotchi will automatically attach coordinates to discovered devices. No extra configuration needed.

### WiGLE upload (optional)

If the `wigle` plugin is enabled and has an API key configured, blegotchi will upload BLE devices to [wigle.net](https://wigle.net) when internet is available. It reuses the wigle plugin's config:

```toml
main.plugins.wigle.enabled = true
main.plugins.wigle.api_key = "your_encoded_api_key"
```

Only devices with GPS coordinates are uploaded. Devices without location data are stored locally but skipped during upload.

## Display

- **Auto mode**: Shows fun personality messages on the pwnagotchi's status line and a `(B_B )` face while scanning
- **Manual mode**: Shows `Found X BLE devices` below the handshake counter

## Data storage

Discovered devices are stored in `ble_devices.json` in the handshakes directory (typically `/home/pi/handshakes/ble_devices.json`). Upload state is tracked in `.blegotchi_uploads`.

## Webhook

Access discovered devices via the pwnagotchi web UI:

```
GET http://<pwnagotchi-ip>:8080/plugins/blegotchi/
```

Returns all devices as JSON.

## License

GPL-3.0
