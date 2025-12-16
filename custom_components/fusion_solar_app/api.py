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
        _LOGGER.info("Starting login process - login_host: %s", self.login_host)
        
        public_key_url = f"https://{self.login_host}{PUBKEY_URL}"
        _LOGGER.info("Getting Public Key at: %s", public_key_url)
        
        try:
            response = self.session.get(public_key_url)
            _LOGGER.info("Pubkey response - Status: %s", response.status_code)
            _LOGGER.debug("Pubkey Response Headers: %s", dict(response.headers))
            _LOGGER.debug("Pubkey Response text (first 500 chars): %s", response.text[:500])
            
            if response.status_code != 200:
                _LOGGER.error("Pubkey request failed with status %s. Response: %s", response.status_code, response.text[:1000])
                self.connected = False
                raise APIAuthError(f"Pubkey request failed with status {response.status_code}")
            
            if not response.text or not response.text.strip():
                _LOGGER.error("Pubkey response is empty")
                self.connected = False
                raise APIAuthError("Pubkey response is empty")
            
            try:
                pubkey_data = response.json()
                _LOGGER.debug("Pubkey JSON parsed successfully")
                _LOGGER.debug("Pubkey Response keys: %s", list(pubkey_data.keys()) if isinstance(pubkey_data, dict) else "Not a dict")
            except ValueError as json_err:
                self.connected = False
                _LOGGER.error("Error processing Pubkey response: JSON format invalid!")
                _LOGGER.error("JSON decode error: %s", json_err)
                _LOGGER.error("Response Headers: %s", dict(response.headers))
                _LOGGER.error("Response text (first 1000 chars): %s", response.text[:1000])
                _LOGGER.error("Response content type: %s", response.headers.get('content-type', 'unknown'))
                raise APIAuthError(f"Error processing Pubkey response: JSON format invalid! {json_err}")
        except requests.exceptions.RequestException as req_err:
            _LOGGER.error("Request exception while getting pubkey: %s", req_err)
            self.connected = False
            raise APIConnectionError(f"Failed to get pubkey: {req_err}") from req_err
        
        
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
        
        _LOGGER.info("Login Request to: %s", login_url)
        _LOGGER.debug("Login payload (password hidden): %s", {k: v if k != 'password' else '***' for k, v in payload.items()})
        _LOGGER.debug("Login headers: %s", headers)
        
        try:
            response = self.session.post(login_url, json=payload, headers=headers)
            _LOGGER.info("Login response - Status: %s", response.status_code)
            _LOGGER.debug("Login Response Headers: %s", dict(response.headers))
            _LOGGER.debug("Login Response text (first 500 chars): %s", response.text[:500])
            
            if response.status_code == 200:
                if not response.text or not response.text.strip():
                    _LOGGER.error("Login response is empty")
                    self.connected = False
                    raise APIAuthError("Login response is empty")
                
                try:
                    login_response = response.json()
                    _LOGGER.debug("Login JSON parsed successfully")
                    _LOGGER.debug("Login Response keys: %s", list(login_response.keys()) if isinstance(login_response, dict) else "Not a dict")
                except ValueError as json_err:
                    self.connected = False
                    _LOGGER.error("Error processing Login response: JSON format invalid!")
                    _LOGGER.error("JSON decode error: %s", json_err)
                    _LOGGER.error("Request Headers: %s", headers)
                    _LOGGER.error("Response Headers: %s", dict(response.headers))
                    _LOGGER.error("Response text (first 1000 chars): %s", response.text[:1000])
                    _LOGGER.error("Response content type: %s", response.headers.get('content-type', 'unknown'))
                    raise APIAuthError(f"Error processing Login response: JSON format invalid! {json_err}")
            else:
                _LOGGER.warning("Login request failed with status %s", response.status_code)
                _LOGGER.debug("Login response text: %s", response.text[:1000])
        except requests.exceptions.RequestException as req_err:
            _LOGGER.error("Request exception during login: %s", req_err)
            self.connected = False
            raise APIConnectionError(f"Login request failed: {req_err}") from req_err
            
            redirect_url = None

            if 'respMultiRegionName' in login_response and login_response['respMultiRegionName']:
                redirect_info = login_response['respMultiRegionName'][1]  # Extract redirect URL
                redirect_url = f"https://{self.login_host}{redirect_info}"
            elif 'redirectURL'in login_response and login_response['redirectURL']:
                redirect_info = login_response['redirectURL']  # Extract redirect URL
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
    
            _LOGGER.info("Redirecting to: %s", redirect_url)
            _LOGGER.debug("Redirect headers: %s", redirect_headers)
            
            try:
                redirect_response = self.session.get(redirect_url, headers=redirect_headers, allow_redirects=True)
                _LOGGER.info("Redirect response - Status: %s, Final URL: %s", redirect_response.status_code, redirect_response.url)
                _LOGGER.debug("Redirect Response text (first 500 chars): %s", redirect_response.text[:500])
                response_headers = redirect_response.headers
                _LOGGER.debug("Redirect Response headers: %s", dict(response_headers))
            except requests.exceptions.RequestException as req_err:
                _LOGGER.error("Request exception during redirect: %s", req_err)
                self.connected = False
                raise APIConnectionError(f"Redirect request failed: {req_err}") from req_err

            # Determine data host from final URL
            self.data_host = urlparse(redirect_response.url).netloc
            _LOGGER.info("Data host determined: %s", self.data_host)

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
                    _LOGGER.info("Getting user ID and CSRF tokens after successful login")
                    self._get_user_id()
                    self.refresh_csrf()
                    
                    _LOGGER.info("Attempting to get station list after login")
                    try:
                        station_data = self.get_station_list()
                        if station_data and "data" in station_data and "list" in station_data["data"] and len(station_data["data"]["list"]) > 0:
                            self.station = station_data["data"]["list"][0]["dn"]
                            _LOGGER.info("Station set successfully to: %s", self.station)
                        else:
                            _LOGGER.error("Failed to get station data from API response")
                            _LOGGER.error("Station data structure: %s", station_data)
                            self.connected = False
                            raise APIAuthError("Failed to get station data")
                    except Exception as station_err:
                        _LOGGER.error("Exception while getting station list: %s", station_err)
                        _LOGGER.error("Exception type: %s", type(station_err).__name__)
                        import traceback
                        _LOGGER.error("Full traceback: %s", traceback.format_exc())
                        self.connected = False
                        raise
                    self._start_session_monitor()
                    return True
                else:
                    _LOGGER.error("No bspsession cookie found in cookies.")
                    _LOGGER.debug("Available cookies: %s", [c.name for c in self.session.cookies])
                    self.connected = False
                    raise APIAuthError("No bspsession cookie found in cookies.")
            else:
                _LOGGER.error("Redirect failed: %s", redirect_response.status_code)
                _LOGGER.error("%s", redirect_response.text)
                self.connected = False
                raise APIAuthError("Redirect failed.")
        else:
            _LOGGER.warning("Login failed: %s", response.status_code)
            _LOGGER.warning("Response headers: %s", response.headers)
            _LOGGER.warning("Response: %s", response.text)
            self.connected = False
            raise APIAuthError("Login failed.")

    def _get_user_id(self):
        """Get user ID dynamically from custom settings endpoint"""
        _LOGGER.info("Getting user ID from custom settings endpoint")
        try:
            if not self.data_host:
                _LOGGER.warning("Cannot get user ID: data_host is not set")
                return
                
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
            
            _LOGGER.debug("Requesting user ID from: %s", custom_settings_url)
            response = self.session.get(custom_settings_url, headers=headers, params=params)
            _LOGGER.debug("Custom settings response status: %s", response.status_code)
            _LOGGER.debug("Custom settings response: %s", response.text[:500])
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    _LOGGER.debug("Custom settings JSON parsed successfully")
                    if 'menuUserChosen' in data and 'userId' in data['menuUserChosen']:
                        self.user_id = data['menuUserChosen']['userId']
                        _LOGGER.info("Got User ID: %s", self.user_id)
                    else:
                        _LOGGER.warning("No userId found in custom settings response. Response keys: %s", list(data.keys()) if isinstance(data, dict) else "Not a dict")
                except ValueError as json_err:
                    _LOGGER.error("Failed to parse custom settings JSON: %s. Response: %s", json_err, response.text[:500])
            else:
                _LOGGER.warning("Custom settings request failed with status %s. Response: %s", response.status_code, response.text[:500])
        except Exception as e:
            _LOGGER.error("Error getting user ID: %s", e)
            import traceback
            _LOGGER.error("Traceback: %s", traceback.format_exc())

    def set_captcha_img(self):
        timestampNow = datetime.now().timestamp() * 1000
        captcha_request_url = f"https://{self.login_host}{CAPTCHA_URL}?timestamp={timestampNow}"
        _LOGGER.error("CAPTCHA Debug - Requesting Captcha at: %s", captcha_request_url)
        _LOGGER.error("CAPTCHA Debug - Using session cookies: %s", dict(self.session.cookies))
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
        
        if not self.data_host:
            _LOGGER.warning("Cannot refresh CSRF: data_host is not set")
            return
        
        if self.csrf is None or datetime.now() - self.csrf_time > timedelta(minutes=5):
            _LOGGER.info("CSRF token needs refresh - data_host: %s", self.data_host)
            endpoint = f"https://{self.data_host}/rest/neteco/auth/v1/keep-alive"
            
            try:
                headers = {
                    "accept": "application/json, text/plain, */*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "Referer": f"https://{self.data_host}/pvmswebsite/assets/build/index.html"
                }
                
                _LOGGER.debug("Getting CSRF at: %s", endpoint)
                _LOGGER.debug("CSRF request headers: %s", headers)
                _LOGGER.debug("Session cookies for CSRF request: %s", dict(self.session.cookies))
                
                response = self.session.get(endpoint, headers=headers)
                _LOGGER.debug("CSRF response status: %s", response.status_code)
                _LOGGER.debug("CSRF response headers: %s", dict(response.headers))
                _LOGGER.debug("CSRF response text (first 200 chars): %s", response.text[:200])
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        _LOGGER.debug("CSRF response JSON parsed successfully")
                        _LOGGER.debug("CSRF response data keys: %s", list(data.keys()) if isinstance(data, dict) else "Not a dict")
                        
                        if 'payload' in data:
                            self.csrf = data['payload']
                            self.csrf_time = datetime.now()
                            _LOGGER.info("CSRF refreshed from 'payload': %s", self.csrf)
                            return
                        elif 'csrfToken' in data:
                            self.csrf = data['csrfToken']
                            self.csrf_time = datetime.now()
                            _LOGGER.info("CSRF refreshed from 'csrfToken': %s", self.csrf)
                            return
                        else:
                            _LOGGER.warning("CSRF response missing expected keys. Response: %s", data)
                    except ValueError as json_err:
                        _LOGGER.error("Failed to parse CSRF JSON response: %s. Response text: %s", json_err, response.text[:500])
                else:
                    _LOGGER.warning("CSRF refresh request failed with status %s. Response: %s", response.status_code, response.text[:500])
            except Exception as e:
                _LOGGER.error("Exception while refreshing CSRF token: %s", e)
                import traceback
                _LOGGER.error("Traceback: %s", traceback.format_exc())
    
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
        """Get station list from API."""
        _LOGGER.info("Getting station list - data_host: %s, connected: %s, csrf: %s", 
                     self.data_host, self.connected, self.csrf is not None)
        
        if not self.data_host:
            _LOGGER.error("Cannot get station list: data_host is not set")
            raise APIAuthError("Data host not set. Login may have failed.")
        
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
            _LOGGER.debug("Added CSRF token to station request headers")
        else:
            _LOGGER.warning("No CSRF token available for station request")
        
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
        
        _LOGGER.info("Requesting station list - URL: %s", station_url)
        _LOGGER.debug("Station request payload: %s", station_payload)
        _LOGGER.debug("Station request headers: %s", station_headers)
        _LOGGER.debug("Session cookies: %s", dict(self.session.cookies))
        
        try:
            station_response = self.session.post(station_url, json=station_payload, headers=station_headers)
            _LOGGER.info("Station list response - Status: %s, URL: %s", station_response.status_code, station_response.url)
            _LOGGER.debug("Station list response headers: %s", dict(station_response.headers))
            _LOGGER.debug("Station list response text (first 500 chars): %s", station_response.text[:500])
            
            if station_response.status_code != 200:
                _LOGGER.error("Station list request failed with status %s. Response: %s", 
                             station_response.status_code, station_response.text[:1000])
                raise APIAuthError(f"Station list request failed with status {station_response.status_code}")
            
            # Check if response is empty
            if not station_response.text or not station_response.text.strip():
                _LOGGER.error("Station list response is empty")
                raise APIAuthError("Station list response is empty")
            
            # Try to parse JSON
            try:
                json_response = station_response.json()
                _LOGGER.debug("Station list JSON parsed successfully")
                _LOGGER.debug("Station list response keys: %s", list(json_response.keys()) if isinstance(json_response, dict) else "Not a dict")
                
                if "data" in json_response:
                    _LOGGER.info("Station list data retrieved successfully")
                    if "list" in json_response["data"]:
                        _LOGGER.info("Found %d stations in list", len(json_response["data"]["list"]))
                        _LOGGER.debug("Station info: %s", json_response["data"])
                    else:
                        _LOGGER.warning("Station list response missing 'list' key in data")
                else:
                    _LOGGER.warning("Station list response missing 'data' key")
                
                return json_response
            except ValueError as json_err:
                _LOGGER.error("Failed to parse station list JSON response. Error: %s", json_err)
                _LOGGER.error("Response status: %s", station_response.status_code)
                _LOGGER.error("Response headers: %s", dict(station_response.headers))
                _LOGGER.error("Response text (first 1000 chars): %s", station_response.text[:1000])
                _LOGGER.error("Response content type: %s", station_response.headers.get('content-type', 'unknown'))
                raise APIAuthError(f"Failed to parse station list JSON: {json_err}")
        except requests.exceptions.RequestException as req_err:
            _LOGGER.error("Request exception while getting station list: %s", req_err)
            raise APIConnectionError(f"Failed to get station list: {req_err}") from req_err

    def get_devices(self) -> list[Device]:
        """Get devices - only returns Panel Production Power sensor."""
        _LOGGER.info("Getting devices - station: %s, data_host: %s", self.station, self.data_host)
        
        if not self.data_host:
            _LOGGER.error("Cannot get devices: data_host is not set")
            raise APIAuthError("Data host not set. Login may have failed.")
        
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
        _LOGGER.info("Requesting energy flow data - URL: %s", data_access_url)
        _LOGGER.debug("Energy flow params: %s", params)
        _LOGGER.debug("Energy flow headers: %s", headers)
        _LOGGER.debug("Session cookies: %s", dict(self.session.cookies))

        output = {
            "panel_production_power": 0.0,
        }

        try:
            response = self.session.get(data_access_url, headers=headers, params=params)
            _LOGGER.info("Energy flow response - Status: %s, URL: %s", response.status_code, response.url)
            _LOGGER.debug("Energy flow response headers: %s", dict(response.headers))
            _LOGGER.debug("Energy flow response text (first 500 chars): %s", response.text[:500])

            if response.status_code == 200:
                # Check if response is empty
                if not response.text or not response.text.strip():
                    _LOGGER.error("Energy flow response is empty")
                    raise APIDataStructureError("Energy flow response is empty")
                
                try:
                    data = response.json()
                    _LOGGER.debug("Energy flow JSON parsed successfully")
                    _LOGGER.debug("Energy flow response keys: %s", list(data.keys()) if isinstance(data, dict) else "Not a dict")
                except ValueError as json_err:
                    _LOGGER.error("Failed to parse energy flow JSON response: %s", json_err)
                    _LOGGER.error("Response status: %s", response.status_code)
                    _LOGGER.error("Response headers: %s", dict(response.headers))
                    _LOGGER.error("Response text (first 1000 chars): %s", response.text[:1000])
                    _LOGGER.error("Response content type: %s", response.headers.get('content-type', 'unknown'))
                    raise APIAuthError(f"Error processing response: JSON format invalid! {json_err}")

                if "data" not in data:
                    _LOGGER.error("Energy flow response missing 'data' key. Response keys: %s", list(data.keys()) if isinstance(data, dict) else "Not a dict")
                    raise APIDataStructureError("Error on data structure: missing 'data' key")
                
                if "flow" not in data["data"]:
                    _LOGGER.error("Energy flow response missing 'flow' key. Data keys: %s", list(data["data"].keys()) if isinstance(data["data"], dict) else "Not a dict")
                    raise APIDataStructureError("Error on data structure: missing 'flow' key")

                # Extract panel production power from nodes
                flow_data_nodes = data["data"]["flow"].get("nodes", [])
                _LOGGER.debug("Found %d nodes in energy flow", len(flow_data_nodes))
                
                panel_found = False
                for node in flow_data_nodes:
                    label = node.get("name", "")
                    value = node.get("description", {}).get("value", "")
                    
                    _LOGGER.debug("Processing node - label: %s, value: %s", label, value)
                    
                    if label == "neteco.pvms.devTypeLangKey.string":
                        output["panel_production_power"] = extract_numeric(value) or 0.0
                        panel_found = True
                        _LOGGER.info("Panel Production Power found: %s kW", output["panel_production_power"])
                        break

                if not panel_found:
                    _LOGGER.warning("Panel production power node not found in energy flow")
                    _LOGGER.debug("Available node labels: %s", [node.get("name", "") for node in flow_data_nodes])
            else:
                _LOGGER.error("Energy flow request failed with status %s", response.status_code)
                _LOGGER.error("Response text (first 1000 chars): %s", response.text[:1000])
                raise APIDataStructureError(f"Error on data structure! Status: {response.status_code}")
        except requests.exceptions.RequestException as req_err:
            _LOGGER.error("Request exception while getting devices: %s", req_err)
            raise APIConnectionError(f"Failed to get devices: {req_err}") from req_err

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
