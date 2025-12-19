"""Fusion Solar App API """

from dataclasses import dataclass
from enum import StrEnum
import logging
import threading
import time
import requests
import json
import base64
from typing import Dict, Optional
from urllib.parse import unquote, urlparse
from datetime import datetime, timedelta, timezone
from .const import DOMAIN, PUBKEY_URL, LOGIN_HEADERS_1_STEP_REFERER, LOGIN_HEADERS_2_STEP_REFERER, LOGIN_VALIDATE_USER_URL, LOGIN_FORM_URL, STATION_LIST_URL, KEEP_ALIVE_URL, CAPTCHA_URL
from .utils import extract_numeric, encrypt_password, generate_nonce

# CAPTCHA solver disabled - manual input only
CAPTCHA_SOLVER_AVAILABLE = False
CaptchaSolver = None

_LOGGER = logging.getLogger(__name__)


class DeviceType(StrEnum):
    """Device types."""

    SENSOR_KW = "sensor"
    SENSOR_KWH = "sensor_kwh"
    SENSOR_PERCENTAGE = "sensor_percentage"
    SENSOR_TIME = "sensor_time"

DEVICES = [
    {"id": "Panel Production Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:solar-panel"},
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

    def __init__(self, user: str, pwd: str, login_host: str, captcha_input: str) -> None:
        """Initialise."""
        self.user = user
        self.pwd = pwd
        self.captcha_input = captcha_input
        self.captcha_img = None
        self.station = None
        self.login_host = login_host
        self.data_host = None
        self.bspsession = ""  # Session cookie for sg5/intl
        self.connected: bool = False
        self.last_session_time: datetime | None = None
        self._session_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.csrf = None
        self.csrf_time = None
        self.user_id = None  # Dynamic user ID
        self.session = requests.Session()  # Use session for cookie persistence
        
        # CAPTCHA solver disabled - use manual input only
        self.captcha_solver = None
        _LOGGER.info("CAPTCHA solver disabled - using manual input only")

    @property
    def controller_name(self) -> str:
        """Return the name of the controller."""
        return DOMAIN


    def login(self) -> bool:
        """Connect to api."""
        
        public_key_url = f"https://{self.login_host}{PUBKEY_URL}"
        _LOGGER.debug("Getting Public Key at: %s", public_key_url)
        
        response = self.session.get(public_key_url)
        _LOGGER.debug("Pubkey Response Headers: %s\r\nResponse: %s", response.headers, response.text)
        try:
            pubkey_data = response.json()
            _LOGGER.debug("Pubkey Response: %s", pubkey_data)
        except Exception as ex:
            self.connected = False
            _LOGGER.error("Error processing Pubkey response: JSON format invalid!\r\nResponse Headers: %s\r\nResponse: %s", response.headers, response.text)
            raise APIAuthError("Error processing Pubkey response: JSON format invalid!\r\nResponse Headers: %s\r\nResponse: %s", response.headers, response.text)
        
        
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
        
        _LOGGER.debug("captcha_input=%s", self.captcha_input)
        if self.captcha_input is not None and self.captcha_input != '':
            payload["verifycode"] = self.captcha_input
            _LOGGER.info("CAPTCHA Debug - Added verifycode to payload: %s", self.captcha_input)
        
        _LOGGER.info("CAPTCHA Debug - Final payload: %s", payload)
        
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
        response = self.session.post(login_url, json=payload, headers=headers)
        _LOGGER.debug("Login: Request Headers: %s\r\nResponse Headers: %s\r\nResponse: %s", headers, response.headers, response.text)
        
        if response.status_code != 200:
            _LOGGER.warning("Login failed: %s", response.status_code)
            _LOGGER.warning("Response headers: %s", response.headers)
            _LOGGER.warning("Response: %s", response.text)
            self.connected = False
            raise APIAuthError("Login failed.")
        
        # Process 200 response
        try:
            login_response = response.json()
            _LOGGER.debug("Login Response: %s", login_response)
        except Exception as ex:
            self.connected = False
            _LOGGER.error("Error processing Login response: JSON format invalid!\r\nRequest Headers: %s\r\nResponse Headers: %s\r\nResponse: %s", headers, response.headers, response.text)
            raise APIAuthError("Error processing Login response: JSON format invalid!\r\nRequest Headers: %s\r\nResponse Headers: %s\r\nResponse: %s", headers, response.headers, response.text)
        
        redirect_url = None

        if 'respMultiRegionName' in login_response and login_response['respMultiRegionName']:
            redirect_info = login_response['respMultiRegionName'][1]  # Extract redirect URL
            redirect_url = f"https://{self.login_host}{redirect_info}"
        elif 'redirectURL' in login_response and login_response['redirectURL']:
            redirect_info = login_response['redirectURL']  # Extract redirect URL
            # Handle both absolute and relative URLs
            if redirect_info.startswith('http'):
                redirect_url = redirect_info
            else:
                redirect_url = f"https://{self.login_host}{redirect_info}"
        else:
            _LOGGER.warning("Login response did not include redirect information.")
            self.connected = False

            if 'errorCode' in login_response and login_response['errorCode']:
                error_code = login_response['errorCode']
                error_msg = login_response.get('errorMsg', 'Unknown error')
                _LOGGER.error("Login failed with error code: %s - %s", error_code, error_msg)
                
                if error_code == '411':
                    _LOGGER.warning("Captcha required.")
                    _LOGGER.info("CAPTCHA Debug - Manual input provided: '%s'", self.captcha_input)
                    
                    # If CAPTCHA was provided but still getting 411, it means the CAPTCHA was incorrect
                    if self.captcha_input and self.captcha_input.strip():
                        _LOGGER.error("CAPTCHA Debug - CAPTCHA was provided but still getting 411 error - CAPTCHA was incorrect")
                        raise APIAuthError("Incorrect CAPTCHA code provided")
                    else:
                        # No CAPTCHA provided, need to show CAPTCHA form
                        _LOGGER.info("CAPTCHA Debug - No CAPTCHA provided, raising CAPTCHA error for manual input handling")
                        raise APIAuthCaptchaError("Login requires Captcha.")
                elif error_code == '401':
                    raise APIAuthError(f"Invalid credentials: {error_msg}")
                else:
                    raise APIAuthError(f"Login failed: {error_code} - {error_msg}")
            else:
                login_form_url = f"https://{self.login_host}{LOGIN_FORM_URL}"
                _LOGGER.debug("Redirecting to Login Form: %s", login_form_url)
                response = self.session.get(login_form_url)
                _LOGGER.debug("Login Form Response: %s", response.text)
                _LOGGER.debug("Login Form Response headers: %s", response.headers)
                raise APIAuthError("Login response did not include redirect information.")

        redirect_headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-encoding": "gzip, deflate, br, zstd",
            "connection": "keep-alive",
            "host": f"{self.login_host}",
            "referer": f"https://{self.login_host}{LOGIN_HEADERS_2_STEP_REFERER}"
        }

        _LOGGER.debug("Redirect to: %s", redirect_url)
        try:
            redirect_response = self.session.get(redirect_url, headers=redirect_headers, allow_redirects=True)
            _LOGGER.debug("Redirect Response status: %s, URL: %s", redirect_response.status_code, redirect_response.url)
            _LOGGER.debug("Redirect Response: %s", redirect_response.text[:500] if redirect_response.text else "Empty")
            response_headers = redirect_response.headers
            _LOGGER.debug("Redirect Response headers: %s", response_headers)

            # Determine data host from final URL
            self.data_host = urlparse(redirect_response.url).netloc
            _LOGGER.debug("Data host: %s", self.data_host)
        except Exception as redirect_err:
            _LOGGER.error("Error during redirect: %s", redirect_err)
            self.connected = False
            raise APIAuthError(f"Redirect failed: {redirect_err}") from redirect_err

        if redirect_response.status_code == 200:
                # Check for bspsession cookie
                session_cookie = None
                
                for cookie in self.session.cookies:
                    if cookie.name == 'bspsession':
                        session_cookie = cookie.value
                        break
                
            if session_cookie:
                _LOGGER.debug("Found bspsession Cookie: %s", session_cookie)
                self.bspsession = session_cookie
                
                self.connected = True
                self.last_session_time = datetime.now(timezone.utc)
                
                # Get user ID and CSRF tokens
                self._get_user_id()
                self.refresh_csrf()
                
                station_data = self.get_station_list()
                if station_data and "data" in station_data and "list" in station_data["data"] and len(station_data["data"]["list"]) > 0:
                    self.station = station_data["data"]["list"][0]["dn"]
                    _LOGGER.info("Station set to: %s", self.station)
                else:
                    _LOGGER.error("Failed to get station data from API response: %s", station_data)
                    self.connected = False
                    raise APIAuthError("Failed to get station data")
                self._start_session_monitor()
                return True
            else:
                _LOGGER.error("No bspsession cookie found in cookies.")
                _LOGGER.debug("Available cookies: %s", [c.name for c in self.session.cookies])
                self.connected = False
                raise APIAuthError("No bspsession cookie found in cookies.")
        else:
            _LOGGER.error("Redirect failed: %s", redirect_response.status_code)
            _LOGGER.error("Redirect response: %s", redirect_response.text[:1000] if redirect_response.text else "Empty")
            self.connected = False
            raise APIAuthError(f"Redirect failed with status {redirect_response.status_code}.")

    def _get_user_id(self):
        """Get user ID dynamically from custom settings endpoint"""
        try:
            custom_settings_url = f"https://{self.data_host}/rest/adminhome/website/v1/customsetting"
            params = {"t": int(time.time() * 1000)}
            headers = {
                'accept': '*/*',
                'accept-language': 'en-GB,en;q=0.7',
                'cache-control': 'no-cache',
                'origin': f'https://{self.data_host}',
                'pragma': 'no-cache',
                'referer': f'https://{self.data_host}/pvmswebsite/assets/build/index.html',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
                'x-non-renewal-session': 'true',
                'x-requested-with': 'XMLHttpRequest'
            }
            
            response = self.session.get(custom_settings_url, headers=headers, params=params)
            _LOGGER.debug("Custom settings response: %s", response.text)
            
            if response.status_code == 200:
                data = response.json()
                if 'menuUserChosen' in data and 'userId' in data['menuUserChosen']:
                    self.user_id = data['menuUserChosen']['userId']
                    _LOGGER.debug("Got User ID: %s", self.user_id)
                else:
                    _LOGGER.warning("No userId found in custom settings response")
            else:
                _LOGGER.warning("Custom settings request failed: %s", response.status_code)
        except Exception as e:
            _LOGGER.error("Error getting user ID: %s", e)

    def _get_cookies_safe(self):
        """Safely get cookies as dict, handling duplicates by taking the first occurrence."""
        cookies_dict = {}
        seen_names = set()
        for cookie in self.session.cookies:
            if cookie.name not in seen_names:
                cookies_dict[cookie.name] = cookie.value
                seen_names.add(cookie.name)
        return cookies_dict

    def set_captcha_img(self):
        timestampNow = datetime.now().timestamp() * 1000
        captcha_request_url = f"https://{self.login_host}{CAPTCHA_URL}?timestamp={timestampNow}"
        _LOGGER.error("CAPTCHA Debug - Requesting Captcha at: %s", captcha_request_url)
        _LOGGER.error("CAPTCHA Debug - Using session cookies: %s", self._get_cookies_safe())
        response = self.session.get(captcha_request_url)
        _LOGGER.error("CAPTCHA Debug - Captcha response status: %d", response.status_code)
        
        if response.status_code == 200:
            self.captcha_img = f"data:image/png;base64,{base64.b64encode(response.content).decode('utf-8')}"
            _LOGGER.error("CAPTCHA Debug - Captcha image created successfully, length: %d", len(self.captcha_img))
        else:
            self.captcha_img = None
            _LOGGER.error("CAPTCHA Debug - Failed to get captcha image, status: %d", response.status_code)

    def refresh_csrf(self):
        """Refresh CSRF token (roarand) for main API endpoints"""
        _LOGGER.info("Refresh CSRF called - Current CSRF: %s, Time since last refresh: %s", 
                     self.csrf, datetime.now() - self.csrf_time if self.csrf_time else "Never")
        
        if self.csrf is None or datetime.now() - self.csrf_time > timedelta(minutes=5):
            _LOGGER.info("CSRF token needs refresh")
            endpoint = f"https://{self.data_host}/rest/neteco/auth/v1/keep-alive"
            
            try:
                headers = {
                    "accept": "application/json, text/plain, */*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "Referer": f"https://{self.data_host}/pvmswebsite/assets/build/index.html"
                }
                
                _LOGGER.debug("Getting CSRF at: %s", endpoint)
                response = self.session.get(endpoint, headers=headers)
                
                if response.status_code == 200:
                    # Check if response is HTML (session expired)
                    content_type = response.headers.get('content-type', '').lower()
                    if 'text/html' in content_type or response.text.strip().startswith('<'):
                        _LOGGER.warning("CSRF refresh returned HTML instead of JSON - session may have expired")
                        self.connected = False
                        return
                    
                    try:
                        data = response.json()
                        if 'payload' in data:
                            self.csrf = data['payload']
                            self.csrf_time = datetime.now()
                            _LOGGER.debug(f"CSRF refreshed: {self.csrf}")
                            return
                        elif 'csrfToken' in data:
                            self.csrf = data['csrfToken']
                            self.csrf_time = datetime.now()
                            _LOGGER.info("CSRF refreshed successfully: %s", self.csrf)
                            return
                    except ValueError as json_err:
                        _LOGGER.warning("CSRF refresh response is not valid JSON: %s", json_err)
                        _LOGGER.debug("Response text (first 200 chars): %s", response.text[:200])
                        self.connected = False
                        return
                else:
                    _LOGGER.warning("CSRF refresh failed with status %s", response.status_code)
            except Exception as e:
                _LOGGER.warning("Could not refresh CSRF token: %s", e)
    
    def _keep_alive_session(self):
        """Keep session alive using events endpoint"""
        try:
            events_url = f"https://{self.data_host}/rest/sysfenw/v1/events"
            params = {
                'indexes': '[13253390,13253390,13253390,13253390,13253390,13253390,13253390,13253390,13253390]',
                'eventIds': '["CloudSOP.sm.privilge.permission.changed","CloudSOP.sm.user.policy.changed","SECONDARY_AUTH_REQUEST_EVENT","cloudsop.fm.website.i18n.refresh","cloudsop.fm.website.alarm.prompt.enabled","cloudsop.fm.website.keytemplate.change","cloudsop.fm.website.alarm.silence.start","cloudsop.fm.website.alarm.silence.stop","cloudsop.sysBroadcast.broadcast"]',
                't': int(time.time() * 1000)
            }
            
            headers = {
                'accept': '*/*',
                'accept-language': 'en-GB,en;q=0.7',
                'cache-control': 'no-cache',
                'origin': f'https://{self.data_host}',
                'pragma': 'no-cache',
                'referer': f'https://{self.data_host}/pvmswebsite/assets/build/index.html',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
                'x-non-renewal-session': 'true',
                'x-requested-with': 'XMLHttpRequest'
            }
            
            response = self.session.get(events_url, headers=headers, params=params)
            if response.status_code == 200:
                _LOGGER.debug("Keep-Alive: SUCCESS")
                return True
            else:
                _LOGGER.warning("Keep-Alive failed: %s", response.status_code)
                return False
                
        except Exception as e:
            _LOGGER.error("Keep-Alive Error: %s", e)
            return False
    
    def get_station_id(self):
        return self.get_station_list()["data"]["list"][0]["dn"]

    def get_station_list(self):
        self.refresh_csrf()

        station_url = f"https://{self.data_host}/rest/pvms/web/station/v1/station/station-list"
        
        # Use appropriate headers based on auth system
        station_headers = {
            "accept": "application/json, text/javascript, */*; q=0.01",
            "accept-language": "en-GB,en;q=0.7",
            "cache-control": "no-cache",
            "content-type": "application/json",
            "origin": f"https://{self.data_host}",
            "pragma": "no-cache",
            "referer": f"https://{self.data_host}/pvmswebsite/assets/build/index.html",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            "x-non-renewal-session": "true",
            "x-requested-with": "XMLHttpRequest",
            "x-timezone-offset": "480"
        }
        
        if self.csrf:
            station_headers["roarand"] = self.csrf
        
        # Use SG5/INTL timezone (Asia/Singapore)
        timezone_offset = 8
        
        station_payload = {
            "curPage": 1,
            "pageSize": 10,
            "gridConnectedTime": "",
            "queryTime": int(time.time() * 1000),
            "timeZone": timezone_offset,
            "sortId": "createTime",
            "sortDir": "DESC",
            "locale": "en_US",
        }
        
        _LOGGER.debug("Getting Station at: %s", station_url)
        station_response = self.session.post(station_url, json=station_payload, headers=station_headers)
        json_response = station_response.json()
        _LOGGER.debug("Station info: %s", json_response["data"])
        return json_response

    def get_devices(self) -> list[Device]:
        """Get devices - only returns Panel Production Power sensor."""
        self.refresh_csrf()

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        
        if self.station is None:
            _LOGGER.error("Station not set. Cannot get devices without station information.")
            return []
        
        params = {"stationDn": unquote(self.station)}
        
        data_access_url = f"https://{self.data_host}/rest/pvms/web/station/v1/overview/energy-flow"
        _LOGGER.debug("Getting Data at: %s", data_access_url)
        response = self.session.get(data_access_url, headers=headers, params=params)

        output = {
            "panel_production_power": 0.0,
        }

        if response.status_code == 200:
            try:
                data = response.json()
                _LOGGER.debug("Get Data Response: %s", data)
            except Exception as ex:
                _LOGGER.error("Error processing response: JSON format invalid! %s", response.text)
                raise APIAuthError("Error processing response: JSON format invalid! %s", response.text)

            if "data" not in data or "flow" not in data["data"]:
                _LOGGER.error("Error on data structure!")
                raise APIDataStructureError("Error on data structure!")

            # Extract panel production power from nodes
            flow_data_nodes = data["data"]["flow"].get("nodes", [])
            
            for node in flow_data_nodes:
                label = node.get("name", "")
                value = node.get("description", {}).get("value", "")
                
                if label == "neteco.pvms.devTypeLangKey.string":
                    output["panel_production_power"] = extract_numeric(value) or 0.0
                    break

            _LOGGER.debug("Panel Production Power: %s kW", output["panel_production_power"])
        else:
            _LOGGER.error("Error on data structure! %s", response.text)
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

    def logout(self) -> bool:
        """Disconnect from api."""
        self.connected = False
        self._stop_session_monitor()
        return True

    def _renew_session(self) -> None:
        """Simulate session renewal."""
        _LOGGER.info("Renewing session.")
        self.connected = False
        self.bspsession = ""
        self.login()

    def _session_monitor(self) -> None:
        """Monitor session and renew if needed."""
        while not self._stop_event.is_set():
            if self.connected == False:
                self._renew_session()
            else:
                # Try to keep session alive
                try:
                    self._keep_alive_session()
                except Exception as e:
                    _LOGGER.warning("Keep-alive failed, will retry: %s", e)
            time.sleep(30)  # Check every 30 seconds

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

        # Try exact match first (for real-time energy sensors)
        if device_id in output:
            value = output[device_id]
        elif device_id.lower().replace(" ", "_") in output:
            value = output[device_id.lower().replace(" ", "_")]
        else:
            raise KeyError(f"'{device_id}' not found.")

        if value is None or value == 'None':
            return default  # Retorna o valor padrão se for None

        try:
            if device_type == DeviceType.SENSOR_KW or device_type == DeviceType.SENSOR_KWH:
               _LOGGER.debug("%s: Value being returned is float: %s", device_id, value)
               return round(float(value), 4)
            else:
                _LOGGER.debug("%s: Value being returned is int: %i", device_id, value)
                return int(value)
        except ValueError:
            _LOGGER.warn(f"Value '{value}' for '{device_id}' can't be converted.")
            return 0.0

class APIAuthError(Exception):
    """Exception class for auth error."""

class APIAuthCaptchaError(Exception):
    """Exception class for auth captcha error."""

class APIConnectionError(Exception):
    """Exception class for connection error."""

class APIDataStructureError(Exception):
    """Exception class for Data error."""
