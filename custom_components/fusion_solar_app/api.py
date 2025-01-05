"""Fusion Solar App API """

from dataclasses import dataclass
from enum import StrEnum
import logging
import threading
import time
import requests
import json
from typing import Dict, Optional
from urllib.parse import unquote, urlparse
from datetime import datetime, timedelta, timezone
from .const import DOMAIN, PUBKEY_URL, LOGIN_HEADERS_1_STEP_REFERER, LOGIN_HEADERS_2_STEP_REFERER, LOGIN_VALIDATE_USER_URL, DATA_URL, STATION_LIST_URL, KEEP_ALIVE_URL, DATA_REFERER_URL
from .utils import extract_numeric, encrypt_password, generate_nonce

_LOGGER = logging.getLogger(__name__)


class DeviceType(StrEnum):
    """Device types."""

    SENSOR = "sensor"
    SENSOR_PERCENTAGE = "sensor_percentage"
    SENSOR_TIME = "sensor_time"

DEVICES = [
    {"id": "House Load Power", "type": DeviceType.SENSOR, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "Panel Production Power", "type": DeviceType.SENSOR, "icon": "mdi:solar-panel"},
    {"id": "Battery Consumption Power", "type": DeviceType.SENSOR, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Injection Power", "type": DeviceType.SENSOR, "icon": "mdi:battery-charging"},
    {"id": "Grid Consumption Power", "type": DeviceType.SENSOR, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Injection Power", "type": DeviceType.SENSOR, "icon": "mdi:transmission-tower-import"},
    {"id": "Battery Percentage", "type": DeviceType.SENSOR_PERCENTAGE, "icon": ""},
    {"id": "Last Authentication Time", "type": DeviceType.SENSOR_TIME, "icon": "mdi:clock-outline"}
]

@dataclass
class Device:
    """FusionSolarAPI device."""

    device_id: str
    device_unique_id: str
    device_type: DeviceType
    name: str
    state: float | int | datetime
    icon: str


class FusionSolarAPI:
    """Class for Fusion Solar App API."""

    def __init__(self, user: str, pwd: str, login_host: str) -> None:
        """Initialise."""
        self.user = user
        self.pwd = pwd
        self.station = None
        self.login_host = login_host
        self.data_host = None
        self.dp_session = ""
        self.connected: bool = False
        self.last_session_time: datetime | None = None
        self._session_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.csrf = None
        self.csrf_time = None

    @property
    def controller_name(self) -> str:
        """Return the name of the controller."""
        return DOMAIN

    def login(self) -> bool:
        """Connect to api."""
        
        public_key_url = f"https://{self.login_host}{PUBKEY_URL}"
        _LOGGER.debug("Getting Public Key at: %s", public_key_url)
        
        response = requests.get(public_key_url)
        pubkey_data = response.json()
        
        pub_key_pem = pubkey_data['pubKey']
        time_stamp = pubkey_data['timeStamp']
        enable_encrypt = pubkey_data['enableEncrypt']
        version = pubkey_data['version']
        
        nonce = generate_nonce()
        
        encrypted_password = encrypt_password(pub_key_pem, self.pwd) + version

        login_url = f"https://{self.login_host}{LOGIN_VALIDATE_USER_URL}?timeStamp={time_stamp}&nonce={nonce}"
        payload = {
            "organizationName": "",
            "password": encrypted_password,
            "username": self.user
        }
        
        headers = {
            "Content-Type": "application/json",
            "accept-encoding": "gzip, deflate, br, zstd",
            "connection": "keep-alive",
            "host": self.login_host,
            "origin": f"https://{self.login_host}",
            "referer": f"https://{self.login_host}{LOGIN_HEADERS_1_STEP_REFERER}",
            "x-requested-with": "XMLHttpRequest"
        }
        
        _LOGGER.debug("Login Request to: %s", login_url)
        response = requests.post(login_url, json=payload, headers=headers)
        if response.status_code == 200:
            try:
                login_response = response.json()
                _LOGGER.debug("Login Response: %s", login_response)
            except Exception as ex:
                self.connected = False
                _LOGGER.debug("Error processing Login response: JSON format invalid!\r\nHeader: %s\r\n%s", headers, response.text)
                raise APIAuthError("Error processing response: JSON format invalid!\r\nHeader: %s\r\n%s", headers, response.text)
        
            if 'respMultiRegionName' in login_response and login_response['respMultiRegionName']:
                redirect_info = login_response['respMultiRegionName'][1]  # Extract redirect URL
                region_name = login_response['respMultiRegionName'][0]
        
                redirect_url = f"https://{self.login_host}{redirect_info}"
                _LOGGER.debug("Login Response: %s", redirect_url)

                redirect_headers = {
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "connection": "keep-alive",
                    "host": "{self.login_host}",
                    "referer": f"https://{self.login_host}{LOGIN_HEADERS_2_STEP_REFERER}"
                }
        
                _LOGGER.debug("Redirect to: %s", redirect_url)
                redirect_response = requests.get(redirect_url, headers=redirect_headers, allow_redirects=False)
                _LOGGER.debug("Redirect Response: %s", redirect_response.text)
                response_headers = redirect_response.headers
                location_header = response_headers.get("Location")
                _LOGGER.debug("Redirect Response headers:")
                for header, value in response_headers.items():
                    _LOGGER.debug(f"{header}: {value}")
                
                self.data_host = urlparse(location_header).netloc

                if redirect_response.status_code == 200 or redirect_response.status_code == 302:
                    cookies = redirect_response.headers.get('Set-Cookie')
                    if cookies:
                        dp_session = None
                        for cookie in cookies.split(';'):
                            if 'dp-session=' in cookie:
                                dp_session = cookie.split('=')[1]
                                break
        
                        if dp_session:
                            _LOGGER.debug("DP Session Cookie: %s", dp_session)
                            self.dp_session = dp_session
                            self.connected = True
                            self.last_session_time = datetime.now(timezone.utc)
                            self.refresh_csrf()
                            self.station = self.get_station_id()
                            self._start_session_monitor()
                            return True
                        else:
                            _LOGGER.debug("DP Session not found in cookies.")
                            self.connected = False
                            raise APIAuthError("DP Session not found in cookies.")
                    else:
                        _LOGGER.debug("No cookies found in the response headers.")
                        self.connected = False
                        raise APIAuthError("No cookies found in the response headers.")
                else:
                    _LOGGER.debug("Redirect failed: %s", redirect_response.status_code)
                    _LOGGER.debug("%s", redirect_response.text)
                    self.connected = False
                    raise APIAuthError("Redirect failed.")
            else:
                _LOGGER.debug("Login response did not include redirect information.")
                self.connected = False
                raise APIAuthError("Login response did not include redirect information.")
        else:
            _LOGGER.debug("Login failed: %s", response.status_code)
            _LOGGER.debug("%s", response.text)
            self.connected = False
            raise APIAuthError("Login failed.")

    def refresh_csrf(self):
        if self.csrf is None or datetime.now() - self.csrf_time > timedelta(minutes=5):
            roarand_url = f"https://{self.data_host}{KEEP_ALIVE_URL}"
            roarand_headers = {
                "accept": "application/json, text/plain, */*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "Referer": f"https://{self.data_host}{DATA_REFERER_URL}"
            }
            roarand_cookies = {
                "locale": "en-us",
                "dp-session": self.dp_session,
            }
            roarand_params = {}
            
            _LOGGER.debug("Getting Roarand at: %s", roarand_url)
            roarand_response = requests.get(roarand_url, headers=roarand_headers, cookies=roarand_cookies, params=roarand_params)
            self.csrf = roarand_response.json()["payload"]
            self.csrf_time = datetime.now()
            _LOGGER.debug(f"CSRF refreshed: {self.csrf}")
    
    def get_station_id(self):
        return self.get_station_list()["data"]["list"][0]["dn"]

    def get_station_list(self):
        self.refresh_csrf()

        station_url = f"https://{self.data_host}{STATION_LIST_URL}"
        
        station_headers = {
                "accept": "application/json, text/javascript, /; q=0.01",
                "accept-encoding": "gzip, deflate, br, zstd",
                "Content-Type": "application/json",
                "Origin": f"https://{self.data_host}",
                "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
                "Roarand": f"{self.csrf}",
            }
        
        station_cookies = {
                "locale": "en-us",
                "dp-session": self.dp_session,
            }
        
        station_payload = {
                "curPage": 1,
                "pageSize": 10,
                "gridConnectedTime": "",
                "queryTime": 1666044000000,
                "timeZone": 2,
                "sortId": "createTime",
                "sortDir": "DESC",
                "locale": "en_US",
            }
        
        _LOGGER.debug("Getting Station at: %s", station_url)
        station_response = requests.post(station_url, json=station_payload, headers=station_headers, cookies=station_cookies)
        json_response = station_response.json()
        _LOGGER.debug("Station info: %s", json_response["data"])
        return json_response

    def logout(self) -> bool:
        """Disconnect from api."""
        self.connected = False
        self._stop_session_monitor()
        return True

    def _renew_session(self) -> None:
        """Simulate session renewal."""
        _LOGGER.info("Renewing session.")
        self.connected = False
        self.dp_session = ""
        self.login()

    def _session_monitor(self) -> None:
        """Monitor session and renew if needed."""
        while not self._stop_event.is_set():
            if self.connected == False:
                self._renew_session()
            time.sleep(60)  # Check every 60 seconds

    def _start_session_monitor(self) -> None:
        """Start the session monitor thread."""
        if self._session_thread is None or not self._session_thread.is_alive():
            self._stop_event.clear()
            self._session_thread = threading.Thread(target=self._session_monitor, daemon=True)
            self._session_thread.start()

    def _stop_session_monitor(self) -> None:
        """Stop the session monitor thread."""
        self._stop_event.set()
        if self._session_thread is not None:
            self._session_thread.join()

    def get_devices(self) -> list[Device]:
        self.refresh_csrf()

        cookies = {
            "locale": "en-us",
            "dp-session": self.dp_session,
        }
        
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        
        # Fusion Solar App Station parameter
        params = {"stationDn": unquote(self.station)}
        
        data_access_url = f"https://{self.data_host}{DATA_URL}"
        _LOGGER.debug("Getting Data at: %s", data_access_url)
        response = requests.get(data_access_url, headers=headers, cookies=cookies, params=params)

        output = {
            "panel_production_power": None,
            "house_load_power": None,
            "grid_consumption_power": None,
            "grid_injection_power": None,
            "battery_injection_power": None,
            "battery_consumption_power": None,
            "battery_percentage": None,
            "exit_code": "SUCCESS",
        }
        
        if response.status_code == 200:
            try:
                data = response.json()
                _LOGGER.debug("Get Data Response: %s", data)
            except Exception as ex:
                self.connected = False
                _LOGGER.debug("Error processing response: JSON format invalid!\r\nCookies: %s\r\nHeader: %s\r\n%s", cookies, headers, response.text)
                raise APIAuthError("Error processing response: JSON format invalid!\r\nCookies: %s\r\nHeader: %s\r\n%s", cookies, headers, response.text)

            if "data" not in data or "flow" not in data["data"]:
                self.connected = False
                _LOGGER.debug("Error on data structure!")
                raise APIDataStructureError("Error on data structure!")

            # Process nodes to gather required information
            flow_data_nodes = data["data"]["flow"].get("nodes", [])
            flow_data_links = data["data"]["flow"].get("links", [])
            node_map = {
                "neteco.pvms.energy.flow.buy.power": "grid_consumption_power",
                "neteco.pvms.devTypeLangKey.string": "panel_production_power",
                "neteco.pvms.devTypeLangKey.energy_store": "battery_injection_power",
                "neteco.pvms.KPI.kpiView.electricalLoad": "house_load_power",
            }
        
            for node in flow_data_nodes:
                label = node.get("name", "")
                value = node.get("description", {}).get("value", "")
                
                if label == "neteco.pvms.devTypeLangKey.energy_store":
                    soc = extract_numeric(node.get("deviceTips", {}).get("SOC", ""))
                    if soc is not None:
                        output["battery_percentage"] = soc
                    
                    battery_power = extract_numeric(node.get("deviceTips", {}).get("BATTERY_POWER", ""))
                    if battery_power is None or battery_power <= 0:
                        output["battery_consumption_power"] = extract_numeric(value)
                        output["battery_injection_power"] = 0.0
                    else:
                        output[node_map[label]] = extract_numeric(value)
                        output["battery_consumption_power"] = 0.0
                else:
                    if label in node_map:
                        output[node_map[label]] = extract_numeric(value)
        
            for node in flow_data_links:
                label = node.get("description", {}).get("label", "")
                value = node.get("description", {}).get("value", "")
                if label in node_map:
                    if label == "neteco.pvms.energy.flow.buy.power" and node.get("flowing", "") == "FORWARD":
                        output[node_map[label]] = extract_numeric(value)
                        output["grid_injection_power"] = 0.0
                    else:
                        output[node_map[label]] = 0.0
                        output["grid_injection_power"] = extract_numeric(value)
            
            output["exit_code"] = "SUCCESS"
            _LOGGER.debug("JSON: %s", json.dumps(output, indent=4))
        else:
            _LOGGER.debug("Error on data structure! %s", response.text)
            self.connected = False
            raise APIDataStructureError("Error on data structure! %s", response.text)

        """Get devices on api."""
        return [
            Device(
                device_id=device.get("id"),
                device_unique_id=self.get_device_unique_id(
                    device.get("id"), device.get("type")
                ),
                device_type=device.get("type"),
                name=self.get_device_name(device.get("id")),
                state=self.get_device_value(device.get("id"), device.get("type"), output),
                icon=device.get("icon")
            )
            for device in DEVICES
        ]

    def get_device_unique_id(self, device_id: str, device_type: DeviceType) -> str:
        """Return a unique device id."""
        return f"{self.controller_name}_{device_id.lower().replace(" ", "_")}"

    def get_device_name(self, device_id: str) -> str:
        """Return the device name."""
        return device_id

    def get_device_value(self, device_id: str, device_type: DeviceType, output: Dict[str, Optional[float | str]], default: int = 0) -> float | int | datetime:
        """Get device random value."""
        if device_type == DeviceType.SENSOR_TIME:
            _LOGGER.debug("%s: Value being returned is datetime: %s", device_id, self.last_session_time)
            return self.last_session_time

        if device_id.lower().replace(" ", "_") not in output:
            raise KeyError(f"'{device_id}' not found.")

        value = output[device_id.lower().replace(" ", "_")]
        if value is None:
            return default  # Retorna o valor padrão se for None

        try:
            if device_type == DeviceType.SENSOR:
               _LOGGER.debug("%s: Value being returned is float: %f", device_id, value)
               return float(value)
            else:
                _LOGGER.debug("%s: Value being returned is int: %i", device_id, value)
                return int(value)
        except ValueError:
            raise ValueError(f"Value '{value}' for '{device_id}' can't be converted to float.")

class APIAuthError(Exception):
    """Exception class for auth error."""

class APIConnectionError(Exception):
    """Exception class for connection error."""

class APIDataStructureError(Exception):
    """Exception class for Data error."""
