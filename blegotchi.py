import csv
import json
import logging
import os
import random
import re
import subprocess
import time
from datetime import datetime, UTC
from io import StringIO
from threading import Lock

import requests

import pwnagotchi
import pwnagotchi.plugins as plugins
import pwnagotchi.ui.faces as faces
import pwnagotchi.ui.fonts as fonts
from pwnagotchi._version import __version__ as __pwnagotchi_version__
from pwnagotchi.ui.components import Text
from pwnagotchi.ui.view import BLACK
from pwnagotchi.utils import StatusFile


class blegotchi(plugins.Plugin):
    __author__ = 'pfefferle'
    __version__ = '0.1.0'
    __license__ = 'GPL3'
    __description__ = 'BLE scanner for pwnagotchi with optional GPS tracking and WiGLE upload'

    RECENT_DEVICE_WINDOW = 300  # 5 minutes

    BLE_FACE = '(B_B )'

    SCAN_MESSAGES = [
        "Sniffing the airwaves for BLE...",
        "Listening for Bluetooth whispers...",
        "Who's broadcasting today?",
        "BLE recon in progress...",
        "Hunting for Bluetooth prey...",
    ]

    NEW_DEVICE_MESSAGES = [
        "Ooh, hello {name}!",
        "New BLE friend: {name}!",
        "Look who showed up: {name}!",
        "Hey there, {name}!",
        "Welcome to my collection, {name}!",
    ]

    FOUND_MANY_MESSAGES = [
        "So many BLE friends here!",
        "Bluetooth party nearby!",
        "The airwaves are buzzing!",
        "BLE devices everywhere!",
        "Quite the crowd today!",
    ]

    FOUND_FEW_MESSAGES = [
        "A few BLE signals around...",
        "Some quiet Bluetooth neighbors.",
        "Not much BLE action here.",
        "A handful of BLE whispers.",
    ]

    FOUND_NONE_MESSAGES = [
        "No BLE devices? How lonely...",
        "The Bluetooth spectrum is silent.",
        "Not a single BLE soul around.",
        "Where did all the BLE go?",
    ]

    MILESTONE_MESSAGES = {
        10: "10 BLE devices! Nice start.",
        50: "50 BLE! Quite the collection.",
        100: "100 BLE! I'm a BLE magnet!",
        250: "250 BLE! Is this all of them?",
        500: "500 BLE! Can't stop sniffing!",
        1000: "1000 BLE! I am the BLE master!",
    }

    def __init__(self):
        self.ready = False
        self.lock = Lock()
        self.report = None
        self.skip = []
        self.options = {}
        self.data = {}
        self.last_scan_time = 0
        self.recent_devices = {}
        self.gps_data = None
        self.handshake_dir = None
        self.devices_file = None
        self.is_auto = False

    def on_loaded(self):
        logging.info("[blegotchi] plugin loaded")

    def on_config_changed(self, config):
        self.handshake_dir = config["bettercap"].get("handshakes")
        self.devices_file = os.path.join(self.handshake_dir, "ble_devices.json")
        self.timer = self.options.get("timer", 45)
        self.bettercap_path = self.options.get("bettercap_path", "/usr/local/bin/bettercap")

        report_filename = os.path.join(self.handshake_dir, ".blegotchi_uploads")
        self.report = StatusFile(report_filename, data_format="json")

        self._load_data()
        self.ready = True
        logging.info("[blegotchi] ready")

    # --- GPS (optional) ---

    def _gps_available(self):
        return plugins.loaded.get('gps') is not None

    def _get_gps(self, agent):
        if not self._gps_available():
            return None
        try:
            gps = agent.session().get("gps", {})
            if gps and gps.get("Latitude") and gps.get("Longitude"):
                return gps
        except Exception as e:
            logging.debug(f"[blegotchi] GPS unavailable: {e}")
        return None

    # --- WiGLE (optional, reuses wigle plugin config) ---

    def _wigle_available(self):
        wigle = plugins.loaded.get('wigle')
        return wigle is not None and wigle.options.get('api_key')

    def _get_wigle_config(self):
        wigle = plugins.loaded.get('wigle')
        if not wigle or not wigle.options:
            return None
        return {
            'api_key': wigle.options.get('api_key', ''),
            'donate': wigle.options.get('donate', False),
            'timeout': wigle.options.get('timeout', 30),
        }

    # --- BLE scanning via Bettercap ---

    def _parse_device_info(self, line):
        name_part = line.split("new BLE device")[1].split("detected as")[0].strip()
        name = 'Unknown' if name_part == '' else name_part
        mac_address = line.split("detected as")[1].split()[0]
        manufacturer_match = re.search(r'\((.*?)\)', line)
        manufacturer = manufacturer_match.group(1) if manufacturer_match else 'Unknown'
        return {'name': name, 'mac_address': mac_address, 'manufacturer': manufacturer}

    def _update_device(self, device_info):
        mac = device_info['mac_address']
        now = datetime.now(tz=UTC).strftime('%Y-%m-%dT%H:%M:%S')
        is_new = mac not in self.data

        if is_new:
            device = {
                'name': device_info['name'],
                'count': 1,
                'manufacturer': device_info['manufacturer'],
                'first_seen': now,
                'last_seen': now,
            }
            if self.gps_data:
                device['latitude'] = self.gps_data.get('Latitude', 0)
                device['longitude'] = self.gps_data.get('Longitude', 0)
                device['altitude'] = self.gps_data.get('Altitude', 0)
                device['accuracy'] = self.gps_data.get('Accuracy', 50)
            self.data[mac] = device
            new_name = device_info['name'] if device_info['name'] != 'Unknown' else None
            return True, new_name

        device = self.data[mac]
        changed = False
        new_name = None

        if device['name'] == 'Unknown' and device_info['name'] != 'Unknown':
            device['name'] = device_info['name']
            changed = True
            new_name = device_info['name']

        if device['manufacturer'] == 'Unknown' and device_info['manufacturer'] != 'Unknown':
            device['manufacturer'] = device_info['manufacturer']
            changed = True

        if self.gps_data and not device.get('latitude'):
            device['latitude'] = self.gps_data.get('Latitude', 0)
            device['longitude'] = self.gps_data.get('Longitude', 0)
            device['altitude'] = self.gps_data.get('Altitude', 0)
            device['accuracy'] = self.gps_data.get('Accuracy', 50)
            changed = True

        last_seen_ts = int(datetime.strptime(device['last_seen'], '%Y-%m-%dT%H:%M:%S').timestamp())
        count_interval = self.options.get('count_interval', 86400)
        if time.time() - last_seen_ts >= count_interval:
            device['count'] += 1
            device['last_seen'] = now
            changed = True

        return changed, new_name

    def scan(self, ui=None):
        if not self.ready:
            return

        if not os.path.exists(self.bettercap_path):
            logging.error(f"[blegotchi] bettercap not found at {self.bettercap_path}")
            return

        logging.info("[blegotchi] scanning...")

        if ui:
            ui.set('face', self.BLE_FACE)
            if self.is_auto:
                ui.set('status', random.choice(self.SCAN_MESSAGES))
            ui.update(force=True)

        cmd = (
            f"{self.bettercap_path} -no-colors -eval "
            "'ble.recon on; events.ignore ble.device.lost; sleep 30; ble.recon off; exit'"
        )
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        except subprocess.CalledProcessError as e:
            logging.error(f"[blegotchi] scan failed: {e}")
            return

        current_time = time.time()
        prev_total = len(self.data)
        changed = False

        for line in output.splitlines():
            if "new BLE device" not in line or "detected as" not in line:
                continue
            device_info = self._parse_device_info(line)
            if not device_info:
                continue

            device_changed, new_name = self._update_device(device_info)
            changed |= device_changed
            self.recent_devices[device_info['mac_address']] = current_time

            if ui and new_name:
                ui.set('face', faces.EXCITED)
                if self.is_auto:
                    ui.set('status', random.choice(self.NEW_DEVICE_MESSAGES).format(name=new_name))

        self.recent_devices = {
            mac: ts for mac, ts in self.recent_devices.items()
            if current_time - ts <= self.RECENT_DEVICE_WINDOW
        }

        if changed:
            self._save_data()

        if ui:
            self._update_ui_after_scan(ui, prev_total)

        logging.info(f"[blegotchi] scan done: {len(self.recent_devices)} recent, {len(self.data)} total")

    def _update_ui_after_scan(self, ui, prev_total):
        num_recent = len(self.recent_devices)
        num_total = len(self.data)
        new_in_scan = num_total - prev_total

        if self.is_auto:
            for threshold, msg in self.MILESTONE_MESSAGES.items():
                if prev_total < threshold <= num_total:
                    ui.set('face', faces.COOL)
                    ui.set('status', msg)
                    break
            else:
                if new_in_scan > 5:
                    ui.set('face', faces.EXCITED)
                    ui.set('status', f"Made {new_in_scan} new BLE friends!")
                elif new_in_scan > 0:
                    ui.set('face', faces.HAPPY)
                    ui.set('status', f"Found {new_in_scan} new BLE device{'s' if new_in_scan > 1 else ''}!")
                elif num_recent > 10:
                    ui.set('face', faces.INTENSE)
                    ui.set('status', random.choice(self.FOUND_MANY_MESSAGES))
                elif num_recent > 0:
                    ui.set('face', faces.LOOK_R)
                    ui.set('status', random.choice(self.FOUND_FEW_MESSAGES))
                else:
                    ui.set('face', faces.LONELY)
                    ui.set('status', random.choice(self.FOUND_NONE_MESSAGES))
        else:
            if new_in_scan > 5:
                ui.set('face', faces.EXCITED)
                ui.set('blegotchi', f"Made {new_in_scan} new BLE friends! {num_total} total")
            elif new_in_scan > 0:
                ui.set('face', faces.HAPPY)
                ui.set('blegotchi', f"Found {new_in_scan} new BLE, {num_total} total")
            elif num_recent > 10:
                ui.set('face', faces.INTENSE)
                ui.set('blegotchi', f"Found {num_total} BLE devices")
            elif num_recent > 0:
                ui.set('blegotchi', f"Found {num_total} BLE devices")
            else:
                ui.set('face', faces.LONELY)
                ui.set('blegotchi', f"Found {num_total} BLE devices")

        ui.update(force=True)

    # --- Storage ---

    def _load_data(self):
        if not os.path.exists(self.devices_file):
            os.makedirs(os.path.dirname(self.devices_file), exist_ok=True)
            self.data = {}
            self._save_data()
            return
        try:
            with open(self.devices_file, 'r') as f:
                self.data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logging.error(f"[blegotchi] failed to load data: {e}")
            self.data = {}

    def _save_data(self):
        try:
            with open(self.devices_file, 'w') as f:
                json.dump(self.data, f)
        except OSError as e:
            logging.error(f"[blegotchi] failed to save data: {e}")

    # --- WiGLE CSV upload (mirrors wigle.py format) ---

    def _generate_csv(self, devices):
        filename = f"{pwnagotchi.name()}_ble_{datetime.now(tz=UTC).strftime('%Y%m%d_%H%M%S')}.csv"

        content = StringIO()
        content.write(
            f"WigleWifi-1.6,appRelease={self.__version__},model=pwnagotchi,"
            f"release={__pwnagotchi_version__},device={pwnagotchi.name()},"
            f"display=kismet,board=RaspberryPi,brand=pwnagotchi,star=Sol,body=3,subBody=0\n"
            f"MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,"
            f"CurrentLatitude,CurrentLongitude,AltitudeMeters,"
            f"AccuracyMeters,RCOIs,MfgrId,Type\n"
        )

        writer = csv.writer(content, delimiter=",", quoting=csv.QUOTE_NONE, escapechar="\\")
        for mac, dev in devices.items():
            try:
                first_seen = datetime.strptime(
                    dev['first_seen'], '%Y-%m-%dT%H:%M:%S'
                ).strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError, KeyError):
                first_seen = datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M:%S')

            writer.writerow([
                mac,
                dev.get('name', 'Unknown'),
                "[LE]",
                first_seen,
                0,
                2412,
                dev.get('rssi', -100),
                dev.get('latitude', 0),
                dev.get('longitude', 0),
                dev.get('altitude', 0),
                dev.get('accuracy', 50),
                "",
                dev.get('manufacturer', ''),
                "BLE",
            ])

        content.seek(0)
        return filename, content

    def _upload_to_wigle(self, reported, csv_filename, csv_content, new_macs, wigle_config):
        try:
            resp = requests.post(
                "https://api.wigle.net/api/v2/file/upload",
                headers={
                    "Authorization": f"Basic {wigle_config['api_key']}",
                    "Accept": "application/json",
                },
                data={"donate": "on" if wigle_config.get('donate') else "false"},
                files={"file": (csv_filename, csv_content, "text/csv")},
                timeout=wigle_config.get('timeout', 30),
            ).json()
            if not resp["success"]:
                raise requests.exceptions.RequestException(resp["message"])
            reported += new_macs
            self.report.update(data={"reported": reported})
            logging.info(f"[blegotchi] uploaded {len(new_macs)} BLE devices to WiGLE")
        except (requests.exceptions.RequestException, OSError) as e:
            self.skip += new_macs
            logging.debug(f"[blegotchi] WiGLE upload failed: {e}")

    # --- Pwnagotchi hooks ---

    def on_ai_ready(self, agent):
        self.is_auto = True

    def on_epoch(self, agent, epoch, epoch_data):
        self.is_auto = True
        self.gps_data = self._get_gps(agent)

    def on_internet_available(self, agent):
        if not self.ready or not self._wigle_available():
            return

        wigle_config = self._get_wigle_config()
        if not wigle_config or not wigle_config.get('api_key'):
            return

        with self.lock:
            reported = self.report.data_field_or("reported", default=[])
            new_devices = {
                mac: dev for mac, dev in self.data.items()
                if mac not in reported
                and mac not in self.skip
                and dev.get('latitude')
                and dev.get('longitude')
            }
            if not new_devices:
                return

            logging.info(f"[blegotchi] uploading {len(new_devices)} BLE devices to WiGLE")
            csv_filename, csv_content = self._generate_csv(new_devices)

            display = agent.view()
            display.on_uploading("wigle.net (BLE)")
            self._upload_to_wigle(reported, csv_filename, csv_content, list(new_devices.keys()), wigle_config)
            display.on_normal()

    def on_ui_setup(self, ui):
        with ui._lock:
            pos = self.options.get("position", (125, 62))
            ui.add_element(
                "blegotchi",
                Text(value="", position=pos, font=fonts.Small, color=BLACK),
            )

    def on_unload(self, ui):
        with ui._lock:
            try:
                ui.remove_element('blegotchi')
            except KeyError:
                pass

    def on_ui_update(self, ui):
        if not self.ready:
            return

        if time.time() - self.last_scan_time >= self.timer:
            self.last_scan_time = time.time()
            self.scan(ui)

        with ui._lock:
            if self.is_auto:
                ui.set('blegotchi', "")
            else:
                ui.set('blegotchi', f"Found {len(self.data)} BLE devices")

    def on_webhook(self, path, request):
        if not self.ready:
            return "not ready"
        return json.dumps(self.data, indent=2)
