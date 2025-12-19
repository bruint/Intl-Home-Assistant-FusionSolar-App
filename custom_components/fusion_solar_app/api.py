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
        
        _LOGGER.info("=== API: login() - Preparing login request ===")
        _LOGGER.info("API - Current captcha_input value: '%s'", self.captcha_input)
        _LOGGER.info("API - captcha_input is not None: %s", self.captcha_input is not None)
        _LOGGER.info("API - captcha_input != '': %s", self.captcha_input != '')
        
        if self.captcha_input is not None and self.captcha_input != '':
            payload["verifycode"] = self.captcha_input
            _LOGGER.info("API - Added verifycode to payload: '%s'", self.captcha_input)
        else:
            _LOGGER.info("API - No verifycode added to payload (captcha_input is None or empty)")
        
        _LOGGER.info("API - Final payload (password hidden): %s", {k: v if k != 'password' else '***' for k, v in payload.items()})
        
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
            _LOGGER.warning("=== LOGIN: No redirect URL in response ===")
            _LOGGER.warning("LOGIN - Full login response: %s", login_response)
            _LOGGER.warning("LOGIN - Response keys: %s", list(login_response.keys()) if isinstance(login_response, dict) else "Not a dict")
            _LOGGER.warning("Login response did not include redirect information.")
            self.connected = False

            if 'errorCode' in login_response and login_response['errorCode']:
                error_code = login_response['errorCode']
                error_msg = login_response.get('errorMsg', 'Unknown error')
                _LOGGER.error("Login failed with error code: %s - %s", error_code, error_msg)
                
                if error_code == '411':
                    _LOGGER.info("=== API: login() - Error 411 (CAPTCHA required) ===")
                    _LOGGER.info("API - Captcha required error received")
                    _LOGGER.info("API - CAPTCHA code that was sent: '%s'", self.captcha_input)
                    _LOGGER.info("API - CAPTCHA code is not None: %s", self.captcha_input is not None)
                    _LOGGER.info("API - CAPTCHA code is not empty: %s", self.captcha_input and self.captcha_input.strip())
                    
                    # If CAPTCHA was provided but still getting 411, it means the CAPTCHA was incorrect
                    if self.captcha_input and self.captcha_input.strip():
                        _LOGGER.warning("API - CAPTCHA was provided ('%s') but still getting 411 error - CAPTCHA was incorrect", self.captcha_input)
                        raise APIAuthError("Incorrect CAPTCHA code provided")
                    else:
                        # No CAPTCHA provided, need to show CAPTCHA form
                        _LOGGER.info("API - No CAPTCHA provided, raising CAPTCHA error for manual input handling")
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
            _LOGGER.warning("=== LOGIN: Redirect completed ===")
            _LOGGER.warning("LOGIN - Redirect URL: %s", redirect_response.url)
            _LOGGER.warning("LOGIN - Data host extracted: %s", self.data_host)
            _LOGGER.warning("LOGIN - Redirect status code: %d", redirect_response.status_code)
            _LOGGER.warning("LOGIN - Session cookies after redirect: %s", self._get_cookies_safe())
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
                
                # Get user ID and keep session alive
                self._get_user_id()
                try:
                    self.refresh_csrf()  # This now uses events endpoint to keep session alive
                except APIAuthError as keep_alive_err:
                    _LOGGER.error("Session keep-alive failed during login: %s", keep_alive_err)
                    self.connected = False
                    raise
                
                try:
                    station_data = self.get_station_list()
                except APIAuthError as station_err:
                    _LOGGER.error("Failed to get station list during login: %s", station_err)
                    self.connected = False
                    raise
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
        _LOGGER.warning("=== API: set_captcha_img() called ===")
        _LOGGER.warning("API - Current captcha_input value: %s", self.captcha_input)
        _LOGGER.warning("API - login_host: %s", self.login_host)
        
        timestampNow = datetime.now().timestamp() * 1000
        captcha_request_url = f"https://{self.login_host}{CAPTCHA_URL}?timestamp={timestampNow}"
        _LOGGER.warning("API - Requesting CAPTCHA image from: %s", captcha_request_url)
        _LOGGER.warning("API - Using session cookies: %s", self._get_cookies_safe())
        
        response = self.session.get(captcha_request_url)
        _LOGGER.warning("API - CAPTCHA response status: %d", response.status_code)
        _LOGGER.warning("API - Response headers: %s", dict(response.headers))
        
        if response.status_code == 200:
            self.captcha_img = f"data:image/png;base64,{base64.b64encode(response.content).decode('utf-8')}"
            _LOGGER.warning("API - CAPTCHA image created successfully, length: %d", len(self.captcha_img))
            _LOGGER.warning("API - CAPTCHA image is base64 data URL: %s", self.captcha_img.startswith("data:image"))
            _LOGGER.info("API - Image data preview: %s", self.captcha_img[:80] + "..." if len(self.captcha_img) > 80 else self.captcha_img)
        else:
            self.captcha_img = None
            _LOGGER.warning("API - Failed to get CAPTCHA image, status: %d", response.status_code)
            _LOGGER.warning("API - Response text: %s", response.text[:200] if response.text else "Empty")

    def refresh_csrf(self):
        """Keep session alive using events endpoint (replaces old CSRF refresh)"""
        if not self.data_host:
            _LOGGER.warning("Cannot keep session alive: data_host is not set")
            self.connected = False
            raise APIAuthError("Cannot keep session alive: data_host is not set. Login may have failed or session expired.")
        
        _LOGGER.warning("=== SESSION KEEP-ALIVE: Starting ===")
        _LOGGER.warning("Keep-Alive - data_host: %s", self.data_host)
        _LOGGER.warning("Keep-Alive - Session cookies: %s", self._get_cookies_safe())
        _LOGGER.warning("Keep-Alive - bspsession cookie: %s", self.bspsession)
        
        try:
            events_url = f"https://{self.data_host}/rest/sysfenw/v1/events"
            params = {
                'indexes': '[4291350,4291350,4291350,4291350,4291350,4291350,4291350,4291350,4291350]',
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
            
            _LOGGER.warning("Keep-Alive - Requesting from endpoint: %s", events_url)
            _LOGGER.warning("Keep-Alive - Request params: %s", params)
            response = self.session.get(events_url, headers=headers, params=params)
            _LOGGER.warning("Keep-Alive - Response status: %d", response.status_code)
            _LOGGER.warning("Keep-Alive - Response URL: %s", response.url)
            
            if response.status_code == 200:
                # Check if response is HTML (session expired)
                content_type = response.headers.get('content-type', '').lower()
                if 'text/html' in content_type or (response.text and response.text.strip().startswith('<')):
                    _LOGGER.warning("Keep-Alive returned HTML instead of JSON - session may have expired")
                    _LOGGER.debug("Response text (first 500 chars): %s", response.text[:500] if response.text else "Empty")
                    self.connected = False
                    raise APIAuthError("Session expired - keep-alive returned HTML")
                
                # Verify we got a valid JSON response (should have relations array)
                try:
                    data = response.json()
                    if 'relations' in data:
                        _LOGGER.warning("Keep-Alive: SUCCESS (session alive)")
                        return
                    else:
                        _LOGGER.warning("Keep-Alive: Unexpected response structure: %s", list(data.keys()) if isinstance(data, dict) else "Not a dict")
                        # Still consider it successful if status is 200
                        return
                except ValueError as json_err:
                    _LOGGER.warning("Keep-Alive response is not valid JSON: %s", json_err)
                    _LOGGER.debug("Response text (first 500 chars): %s", response.text[:500] if response.text else "Empty")
                    self.connected = False
                    raise APIAuthError(f"Session expired - keep-alive returned invalid JSON: {json_err}")
            else:
                _LOGGER.error("Keep-Alive failed with status %d", response.status_code)
                _LOGGER.error("Keep-Alive - Response text (first 500 chars): %s", response.text[:500] if response.text else "Empty")
                self.connected = False
                raise APIAuthError(f"Session keep-alive failed with status {response.status_code}")
        except APIAuthError:
            raise
        except Exception as e:
            _LOGGER.error("Could not keep session alive: %s", e)
            self.connected = False
            raise APIAuthError(f"Session keep-alive failed: {e}") from e
    
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
        if not self.data_host:
            _LOGGER.error("Cannot get station list: data_host is not set")
            raise APIAuthError("Data host not set. Login may have failed.")
        
        try:
            self.refresh_csrf()  # Keep session alive
        except APIAuthError as e:
            _LOGGER.error("Session keep-alive failed, cannot get station list: %s", e)
            raise

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
        
        # Check response status
        if station_response.status_code != 200:
            _LOGGER.error("Station list request failed with status %s", station_response.status_code)
            _LOGGER.debug("Response text (first 500 chars): %s", station_response.text[:500] if station_response.text else "Empty")
            self.connected = False
            raise APIAuthError(f"Station list request failed with status {station_response.status_code}")
        
        # Check if response is empty
        if not station_response.text or not station_response.text.strip():
            _LOGGER.error("Station list response is empty")
            self.connected = False
            raise APIAuthError("Station list response is empty")
        
        # Check if response is HTML (session expired)
        content_type = station_response.headers.get('content-type', '').lower()
        if 'text/html' in content_type or (station_response.text and station_response.text.strip().startswith('<')):
            _LOGGER.error("Station list returned HTML instead of JSON - session may have expired")
            _LOGGER.debug("Response text (first 500 chars): %s", station_response.text[:500] if station_response.text else "Empty")
            self.connected = False
            raise APIAuthError("Session expired - station list returned HTML")
        
        # Try to parse JSON
        try:
            json_response = station_response.json()
            _LOGGER.debug("Station info: %s", json_response.get("data", "No data key"))
            return json_response
        except ValueError as json_err:
            _LOGGER.error("Failed to parse station list JSON response: %s", json_err)
            _LOGGER.error("Response status: %s", station_response.status_code)
            _LOGGER.error("Response headers: %s", dict(station_response.headers))
            _LOGGER.error("Response text (first 1000 chars): %s", station_response.text[:1000] if station_response.text else "Empty")
            _LOGGER.error("Response content type: %s", station_response.headers.get('content-type', 'unknown'))
            self.connected = False
            raise APIAuthError(f"Failed to parse station list JSON: {json_err}")

    def get_devices(self) -> list[Device]:
        """Get devices - only returns Panel Production Power sensor."""
        if not self.data_host:
            _LOGGER.error("Cannot get devices: data_host is not set")
            raise APIAuthError("Data host not set. Login may have failed.")
        
        try:
            self.refresh_csrf()  # Keep session alive
        except APIAuthError as e:
            _LOGGER.error("Session keep-alive failed, cannot get devices: %s", e)
            raise

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

        if response.status_code != 200:
            _LOGGER.error("Energy flow request failed with status %s", response.status_code)
            _LOGGER.debug("Response text (first 500 chars): %s", response.text[:500] if response.text else "Empty")
            self.connected = False
            raise APIAuthError(f"Energy flow request failed with status {response.status_code}")

        # Check if response is empty
        if not response.text or not response.text.strip():
            _LOGGER.error("Energy flow response is empty")
            self.connected = False
            raise APIAuthError("Energy flow response is empty")

        # Check if response is HTML (session expired)
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' in content_type or (response.text and response.text.strip().startswith('<')):
            _LOGGER.error("Energy flow returned HTML instead of JSON - session may have expired")
            _LOGGER.debug("Response text (first 500 chars): %s", response.text[:500] if response.text else "Empty")
            self.connected = False
            raise APIAuthError("Session expired - energy flow returned HTML")

        try:
            data = response.json()
            _LOGGER.debug("Get Data Response: %s", data)
        except ValueError as json_err:
            _LOGGER.error("Error processing response: JSON format invalid! %s", json_err)
            _LOGGER.error("Response text (first 1000 chars): %s", response.text[:1000] if response.text else "Empty")
            self.connected = False
            raise APIAuthError(f"Error processing response: JSON format invalid! {json_err}")

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
        return f"{self.controller_name}_{device_id.lower().replace(' ', '_')}"

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
            _LOGGER.warning("Value '%s' for '%s' can't be converted.", value, device_id)
            return 0.0

class APIAuthError(Exception):
    """Exception class for auth error."""

class APIAuthCaptchaError(Exception):
    """Exception class for auth captcha error."""

class APIConnectionError(Exception):
    """Exception class for connection error."""

class APIDataStructureError(Exception):
    """Exception class for Data error."""
