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
from urllib.parse import unquote, quote, urlparse, urlencode
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
from .const import DOMAIN, PUBKEY_URL, LOGIN_HEADERS_1_STEP_REFERER, LOGIN_HEADERS_2_STEP_REFERER, LOGIN_VALIDATE_USER_URL, LOGIN_FORM_URL, DATA_URL, STATION_LIST_URL, KEEP_ALIVE_URL, DATA_REFERER_URL, ENERGY_BALANCE_URL, LOGIN_DEFAULT_REDIRECT_URL, CAPTCHA_URL
from .utils import extract_numeric, encrypt_password, generate_nonce

_LOGGER = logging.getLogger(__name__)


class DeviceType(StrEnum):
    """Device types."""

    SENSOR_KW = "sensor"
    SENSOR_KWH = "sensor_kwh"
    SENSOR_PERCENTAGE = "sensor_percentage"
    SENSOR_TIME = "sensor_time"

class ENERGY_BALANCE_CALL_TYPE(StrEnum):
    """Device types."""

    DAY = "2"
    PREVIOUS_MONTH = "3"
    MONTH = "4"
    YEAR = "5"
    LIFETIME = "6"

DEVICES = [
    {"id": "House Load Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "Panel Production Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Battery Consumption Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Injection Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Grid Consumption Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Injection Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Battery Percentage", "type": DeviceType.SENSOR_PERCENTAGE, "icon": ""},
    {"id": "Battery Capacity", "type": DeviceType.SENSOR_KW, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "Last Authentication Time", "type": DeviceType.SENSOR_TIME, "icon": "mdi:clock-outline"},
    
    # Real-time interval energy sensors for Energy Dashboard
    {"id": "Solar Production Energy (Real-time)", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Grid Consumption Energy (Real-time)", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Injection Energy (Real-time)", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Battery Consumption Energy (Real-time)", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Injection Energy (Real-time)", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
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


class PowerIntegrator:
    """Class to integrate power over time for real-time energy calculations."""
    
    def __init__(self):
        self.last_update: datetime | None = None
        self.last_power: float = 0.0
        self.accumulated_energy: float = 0.0
        self.day_start: datetime | None = None
    
    def update(self, power: float, current_time: datetime) -> float:
        """Update the integrator with new power reading and return accumulated energy."""
        # Reset at midnight
        if self.day_start is None or current_time.date() != self.day_start.date():
            self.day_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
            self.accumulated_energy = 0.0
            self.last_update = None
        
        # Calculate energy since last update using trapezoidal rule
        if self.last_update is not None:
            time_diff_hours = (current_time - self.last_update).total_seconds() / 3600
            # Average power over the interval
            avg_power = (power + self.last_power) / 2
            energy_increment = avg_power * time_diff_hours
            self.accumulated_energy += energy_increment
        
        # Update state
        self.last_update = current_time
        self.last_power = power
        
        return self.accumulated_energy


class FusionSolarAPI:
    """Class for Fusion Solar App API."""

    def __init__(self, user: str, pwd: str, login_host: str, captcha_input: str) -> None:
        """Initialise."""
        self.user = user
        self.pwd = pwd
        self.captcha_input = captcha_input
        self.captcha_img = None
        self.station = None
        self.battery_capacity = None
        self.login_host = login_host
        self.data_host = None
        self.dp_session = ""
        self.bspsession = ""  # For old auth system (sg5/intl)
        self.session_cookie_name = ""  # Will be set to 'dp-session' or 'bspsession'
        self.connected: bool = False
        self.last_session_time: datetime | None = None
        self._session_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.csrf = None
        self.csrf_time = None
        self.uni_csrf = None  # For keep-alive endpoints
        self.uni_csrf_time = None
        self.user_id = None  # Dynamic user ID
        self.session = requests.Session()  # Use session for cookie persistence
        
        # Power integrators for real-time energy calculation
        self.solar_integrator = PowerIntegrator()
        self.grid_consumption_integrator = PowerIntegrator()
        self.grid_injection_integrator = PowerIntegrator()
        self.battery_consumption_integrator = PowerIntegrator()
        self.battery_injection_integrator = PowerIntegrator()

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
        if response.status_code == 200:
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
            redirect_response = self.session.get(redirect_url, headers=redirect_headers, allow_redirects=True)
            _LOGGER.debug("Redirect Response: %s", redirect_response.text)
            response_headers = redirect_response.headers
            _LOGGER.debug("Redirect Response headers: %s", response_headers)

            # Determine data host from final URL
            self.data_host = urlparse(redirect_response.url).netloc
            _LOGGER.debug("Data host: %s", self.data_host)

            if redirect_response.status_code == 200:
                # Check for session cookies in the session object
                session_cookie = None
                session_cookie_name = None
                
                for cookie in self.session.cookies:
                    if cookie.name in ['dp-session', 'bspsession']:
                        session_cookie = cookie.value
                        session_cookie_name = cookie.name
                        break
                
                if session_cookie:
                    _LOGGER.debug("Found %s Cookie: %s", session_cookie_name, session_cookie)
                    self.session_cookie_name = session_cookie_name
                    if session_cookie_name == 'dp-session':
                        self.dp_session = session_cookie
                    else:
                        self.bspsession = session_cookie
                    
                    self.connected = True
                    self.last_session_time = datetime.now(timezone.utc)
                    
                    # Get user ID and CSRF tokens
                    self._get_user_id()
                    self.refresh_csrf()
                    
                    station_data = self.get_station_list()
                    self.station = station_data["data"]["list"][0]["dn"]
                    if self.battery_capacity is None or self.battery_capacity == 0.0:
                        self.battery_capacity = station_data["data"]["list"][0]["batteryCapacity"]
                    self._start_session_monitor()
                    return True
                else:
                    _LOGGER.error("No session cookie found in cookies.")
                    _LOGGER.debug("Available cookies: %s", [c.name for c in self.session.cookies])
                    self.connected = False
                    raise APIAuthError("No session cookie found in cookies.")
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

    def set_captcha_img(self):
        timestampNow = datetime.now().timestamp() * 1000
        captcha_request_url = f"https://{self.login_host}{CAPTCHA_URL}?timestamp={timestampNow}"
        _LOGGER.debug("Requesting Captcha at: %s", captcha_request_url)
        response = self.session.get(captcha_request_url)
        
        if response.status_code == 200:
            self.captcha_img = f"data:image/png;base64,{base64.b64encode(response.content).decode('utf-8')}"
        else:
            self.captcha_img = None

    def refresh_csrf(self):
        """Refresh CSRF token (roarand) for main API endpoints"""
        if self.csrf is None or datetime.now() - self.csrf_time > timedelta(minutes=5):
            # Try different keep-alive endpoints based on auth system
            endpoints = [
                f"https://{self.data_host}/rest/dpcloud/auth/v1/keep-alive",
                f"https://{self.data_host}/rest/neteco/auth/v1/keep-alive", 
                f"https://{self.data_host}/unisess/v1/auth/session"
            ]
            
            for endpoint in endpoints:
                try:
                    headers = {
                        "accept": "application/json, text/plain, */*",
                        "accept-encoding": "gzip, deflate, br, zstd",
                        "Referer": f"https://{self.data_host}/pvmswebsite/assets/build/index.html"
                    }
                    
                    _LOGGER.debug("Getting CSRF at: %s", endpoint)
                    response = self.session.get(endpoint, headers=headers)
                    
                    if response.status_code == 200:
                        data = response.json()
                        if 'payload' in data:
                            self.csrf = data['payload']
                            self.csrf_time = datetime.now()
                            _LOGGER.debug(f"CSRF refreshed: {self.csrf}")
                            return
                        elif 'csrfToken' in data:
                            self.csrf = data['csrfToken']
                            self.csrf_time = datetime.now()
                            _LOGGER.debug(f"CSRF refreshed: {self.csrf}")
                            return
                except Exception as e:
                    _LOGGER.debug("CSRF endpoint %s failed: %s", endpoint, e)
                    continue
            
            _LOGGER.warning("Could not refresh CSRF token from any endpoint")
    
    def refresh_uni_csrf(self):
        """Refresh UNI CSRF token (x-uni-crsf-token) for keep-alive endpoints"""
        if self.uni_csrf is None or datetime.now() - self.uni_csrf_time > timedelta(minutes=5):
            # Try different endpoints that might return the uni CSRF token
            endpoints = [
                f"https://{self.data_host}/febs/21.40.38/users/profile",
                f"https://{self.data_host}/rest/sysfenw/v1/events",
                f"https://{self.data_host}/unisess/v1/auth/session"
            ]
            
            for endpoint in endpoints:
                try:
                    response = self.session.get(endpoint)
                    if response.status_code == 200:
                        # Check response headers for CSRF token
                        csrf_header = response.headers.get('x-uni-crsf-token') or response.headers.get('X-Uni-Crsf-Token')
                        if csrf_header:
                            self.uni_csrf = csrf_header
                            self.uni_csrf_time = datetime.now()
                            _LOGGER.debug(f"UNI CSRF refreshed: {self.uni_csrf}")
                            return
                        
                        # Check response body
                        try:
                            data = response.json()
                            if 'csrfToken' in data:
                                self.uni_csrf = data['csrfToken']
                                self.uni_csrf_time = datetime.now()
                                _LOGGER.debug(f"UNI CSRF refreshed: {self.uni_csrf}")
                                return
                        except:
                            pass
                except Exception as e:
                    _LOGGER.debug("UNI CSRF endpoint %s failed: %s", endpoint, e)
                    continue
            
            _LOGGER.warning("Could not refresh UNI CSRF token from any endpoint")
    
    def _keep_alive_session(self):
        """Implement both keep-alive mechanisms"""
        if not self.user_id:
            _LOGGER.warning("No user ID available for keep-alive")
            return False
        
        self.refresh_uni_csrf()
        if not self.uni_csrf:
            _LOGGER.warning("No UNI CSRF token available for keep-alive")
            return False
        
        success_count = 0
        
        # 1. User Profile Keep-Alive
        try:
            profile_url = f"https://{self.data_host}/febs/21.40.38/users/{self.user_id}/profile"
            headers = {
                'accept': 'application/json',
                'accept-language': 'en-GB,en;q=0.7',
                'cache-control': 'no-cache',
                'origin': f'https://{self.data_host}',
                'pragma': 'no-cache',
                'referer': f'https://{self.data_host}/pvmswebsite/assets/build/index.html',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
                'x-non-renewal-session': 'true',
                'x-requested-with': 'XMLHttpRequest',
                'x-uni-crsf-token': self.uni_csrf,
                'x-user-id': str(self.user_id)
            }
            
            response = self.session.get(profile_url, headers=headers)
            if response.status_code == 200:
                _LOGGER.debug("Profile Keep-Alive: SUCCESS")
                success_count += 1
            else:
                _LOGGER.warning("Profile Keep-Alive failed: %s", response.status_code)
                
        except Exception as e:
            _LOGGER.error("Profile Keep-Alive Error: %s", e)
        
        # 2. System Events Keep-Alive
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
                _LOGGER.debug("Events Keep-Alive: SUCCESS")
                success_count += 1
            else:
                _LOGGER.warning("Events Keep-Alive failed: %s", response.status_code)
                
        except Exception as e:
            _LOGGER.error("Events Keep-Alive Error: %s", e)
        
        _LOGGER.debug("Keep-Alive Summary: %d/2 successful", success_count)
        return success_count > 0
    
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
        
        # Use appropriate timezone based on auth system
        timezone_offset = 2 if self.session_cookie_name == 'dp-session' else 8
        
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
        self.refresh_csrf()

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        
        # Fusion Solar App Station parameter
        params = {"stationDn": unquote(self.station)}
        
        data_access_url = f"https://{self.data_host}/rest/pvms/web/station/v1/overview/energy-flow"
        _LOGGER.debug("Getting Data at: %s", data_access_url)
        response = self.session.get(data_access_url, headers=headers, params=params)

        output = {
            "panel_production_power": 0.0,
            "panel_production_today": 0.0,
            "panel_production_week": 0.0,
            "panel_production_month": 0.0,
            "panel_production_year": 0.0,
            "panel_production_lifetime": 0.0,
            "panel_production_consumption_today": 0.0,
            "panel_production_consumption_week": 0.0,
            "panel_production_consumption_month": 0.0,
            "panel_production_consumption_year": 0.0,
            "panel_production_consumption_lifetime": 0.0,
            "house_load_power": 0.0,
            "house_load_today": 0.0,
            "house_load_week": 0.0,
            "house_load_month": 0.0,
            "house_load_year": 0.0,
            "house_load_lifetime": 0.0,
            "grid_consumption_power": 0.0,
            "grid_consumption_today": 0.0,
            "grid_consumption_week": 0.0,
            "grid_consumption_month": 0.0,
            "grid_consumption_year": 0.0,
            "grid_consumption_lifetime": 0.0,
            "grid_injection_power": 0.0,
            "grid_injection_today": 0.0,
            "grid_injection_week": 0.0,
            "grid_injection_month": 0.0,
            "grid_injection_year": 0.0,
            "grid_injection_lifetime": 0.0,
            "battery_injection_power": 0.0,
            "battery_injection_today": 0.0,
            "battery_injection_week": 0.0,
            "battery_injection_month": 0.0,
            "battery_injection_year": 0.0,
            "battery_injection_lifetime": 0.0,
            "battery_consumption_power": 0.0,
            "battery_consumption_today": 0.0,
            "battery_consumption_week": 0.0,
            "battery_consumption_month": 0.0,
            "battery_consumption_year": 0.0,
            "battery_consumption_lifetime": 0.0,
            "battery_percentage": 0.0,
            "battery_capacity": 0.0,
            "exit_code": "SUCCESS",
        }

        if response.status_code == 200:
            try:
                data = response.json()
                _LOGGER.debug("Get Data Response: %s", data)
            except Exception as ex:
                _LOGGER.error("Error processing response: JSON format invalid!\r\nCookies: %s\r\nHeader: %s\r\n%s", cookies, headers, response.text)
                raise APIAuthError("Error processing response: JSON format invalid!\r\nCookies: %s\r\nHeader: %s\r\n%s", cookies, headers, response.text)

            if "data" not in data or "flow" not in data["data"]:
                _LOGGER.error("Error on data structure!")
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
                    if label == "neteco.pvms.energy.flow.buy.power":
                        grid_consumption_injection = extract_numeric(value)
                        if (output["panel_production_power"] + output["battery_consumption_power"] - output["battery_injection_power"] - output["house_load_power"]) > 0:
                            output["grid_injection_power"] = grid_consumption_injection
                            output["grid_consumption_power"] = 0.0
                        else:
                            output["grid_consumption_power"] = grid_consumption_injection
                            output["grid_injection_power"] = 0.0

            self.update_output_with_battery_capacity(output)
            self.update_output_with_energy_balance(output)
            
            # Calculate real-time energy using power integration
            current_time = datetime.now()
            output["Solar Production Energy (Real-time)"] = self.solar_integrator.update(output["panel_production_power"], current_time)
            output["Grid Consumption Energy (Real-time)"] = self.grid_consumption_integrator.update(output["grid_consumption_power"], current_time)
            output["Grid Injection Energy (Real-time)"] = self.grid_injection_integrator.update(output["grid_injection_power"], current_time)
            output["Battery Consumption Energy (Real-time)"] = self.battery_consumption_integrator.update(output["battery_consumption_power"], current_time)
            output["Battery Injection Energy (Real-time)"] = self.battery_injection_integrator.update(output["battery_injection_power"], current_time)

            output["exit_code"] = "SUCCESS"
            _LOGGER.debug("output JSON: %s", output)
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

    def update_output_with_battery_capacity(self, output: Dict[str, Optional[float | str]]):
        if self.battery_capacity is None or self.battery_capacity == 0.0:
            _LOGGER.debug("Getting Battery capacity")
            self.refresh_csrf()
            station_list = self.get_station_list()
            station_data = station_list["data"]["list"][0]
            output["battery_capacity"] = station_data["batteryCapacity"]
            self.battery_capacity = station_data["batteryCapacity"]
        else:
            output["battery_capacity"] = self.battery_capacity
    
    def update_output_with_energy_balance(self, output: Dict[str, Optional[float | str]]):
        self.refresh_csrf()
        
        # Month energy sensors
        _LOGGER.debug("Getting Month's energy data")
        month_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.MONTH)
        output["panel_production_month"] = extract_numeric(month_data["data"]["totalProductPower"])
        output["panel_production_consumption_month"] = extract_numeric(month_data["data"]["totalSelfUsePower"])
        output["grid_injection_month"] = extract_numeric(month_data["data"]["totalOnGridPower"])
        output["grid_consumption_month"] = extract_numeric(month_data["data"]["totalBuyPower"])
        
        month_charge_power_list = month_data["data"]["chargePower"]
        if month_charge_power_list:
            month_total_charge_power = sum(extract_numeric(value) for value in month_charge_power_list if (value != "--" and value != "null"))
            output["battery_injection_month"] = month_total_charge_power
        
        month_discharge_power_list = month_data["data"]["dischargePower"]
        if month_discharge_power_list:
            month_total_discharge_power = sum(extract_numeric(value) for value in month_discharge_power_list if (value != "--" and value != "null"))
            output["battery_consumption_month"] = month_total_discharge_power

        # Today energy sensors - Use real-time KPI data instead of monthly arrays
        _LOGGER.debug("Getting Today's energy data from real-time KPI")
        try:
            # Get real-time KPI data for today's values
            kpi_url = f"https://{self.data_host}/rest/pvms/web/station/v1/station/total-real-kpi"
            kpi_params = {
                "queryTime": int(time.time() * 1000),
                "timeZone": 1 if self.session_cookie_name == 'dp-session' else 8,
                "_": int(time.time() * 1000)
            }
            kpi_headers = {
                "accept": "application/json, text/javascript, */*; q=0.01",
                "accept-language": "en-GB,en;q=0.7",
                "cache-control": "no-cache",
                "origin": f"https://{self.data_host}",
                "pragma": "no-cache",
                "referer": f"https://{self.data_host}/pvmswebsite/assets/build/index.html",
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                "x-non-renewal-session": "true",
                "x-requested-with": "XMLHttpRequest"
            }
            
            # Add CSRF token if available
            if self.csrf:
                kpi_headers["roarand"] = self.csrf
            
            kpi_response = self.session.get(kpi_url, headers=kpi_headers, params=kpi_params)
            _LOGGER.debug("KPI Response status: %s", kpi_response.status_code)
            if kpi_response.status_code == 200:
                kpi_data = kpi_response.json()
                _LOGGER.debug("KPI Response data: %s", kpi_data)
                if kpi_data.get("success") and "data" in kpi_data:
                    kpi_info = kpi_data["data"]
                    
                    # Use real-time KPI data for today's values
                    daily_energy = kpi_info.get("dailyEnergy", 0)
                    daily_charge = kpi_info.get("dailyChargeCapacity", 0)
                    daily_discharge = kpi_info.get("dailyDisChargeCapacity", 0)
                    
                    _LOGGER.debug("Raw KPI values: dailyEnergy=%s, dailyCharge=%s, dailyDischarge=%s", 
                                 daily_energy, daily_charge, daily_discharge)
                    
                    # Convert to float directly (KPI data is already numeric)
                    output["panel_production_today"] = float(daily_energy) if daily_energy is not None else 0.0
                    output["battery_injection_today"] = float(daily_charge) if daily_charge is not None else 0.0
                    output["battery_consumption_today"] = float(daily_discharge) if daily_discharge is not None else 0.0
                    
                    _LOGGER.debug("Today's data from KPI: production=%s, battery_charge=%s, battery_discharge=%s", 
                                 output["panel_production_today"], 
                                 output["battery_injection_today"], 
                                 output["battery_consumption_today"])
                else:
                    _LOGGER.warning("KPI data not available or unsuccessful: %s", kpi_data)
            else:
                _LOGGER.warning("Failed to get KPI data: %s - %s", kpi_response.status_code, kpi_response.text)
        except Exception as e:
            _LOGGER.error("Error getting today's KPI data: %s", e)
        
        # Fallback to monthly data if KPI data is not available or incomplete
        if output["panel_production_today"] == 0.0:
            _LOGGER.debug("KPI data was 0, trying fallback methods")
            
            # Try station list data as fallback
            try:
                station_data = self.get_station_list()
                if station_data.get("success") and "data" in station_data and "list" in station_data["data"]:
                    station_list = station_data["data"]["list"]
                    if len(station_list) > 0:
                        station_info = station_list[0]
                        # Try to get daily energy from station data
                        if "dailyEnergy" in station_info:
                            output["panel_production_today"] = extract_numeric(station_info["dailyEnergy"])
                            _LOGGER.debug("Got today's production from station list: %s", output["panel_production_today"])
            except Exception as e:
                _LOGGER.debug("Station list fallback failed: %s", e)
            
            # Try monthly data as last resort
            if output["panel_production_today"] == 0.0:
                month_panel_production_list = month_data["data"]["productPower"]
                if month_panel_production_list and len(month_panel_production_list) > datetime.now().day - 1:
                    panel_production_value_today = month_panel_production_list[datetime.now().day - 1]
                    if panel_production_value_today != "--" and panel_production_value_today != "null":
                        output["panel_production_today"] = extract_numeric(panel_production_value_today)
                        _LOGGER.debug("Got today's production from monthly data: %s", output["panel_production_today"])
        
        if output["battery_injection_today"] == 0.0 and month_charge_power_list:
            if len(month_charge_power_list) > datetime.now().day - 1:
                charge_value_today = month_charge_power_list[datetime.now().day - 1]
                if charge_value_today != "--" and charge_value_today != "null":
                    output["battery_injection_today"] = extract_numeric(charge_value_today)

        if output["battery_consumption_today"] == 0.0 and month_discharge_power_list:
            if len(month_discharge_power_list) > datetime.now().day - 1:
                discharge_value_today = month_discharge_power_list[datetime.now().day - 1]
                if discharge_value_today != "--" and discharge_value_today != "null":
                    output["battery_consumption_today"] = extract_numeric(discharge_value_today)

        # Get week data for grid consumption/injection
        try:
            week_data = self.get_week_data()
            if week_data and len(week_data) > 0:
                output["grid_consumption_today"] = extract_numeric(week_data[-1]["data"]["totalBuyPower"])
                output["grid_injection_today"] = extract_numeric(week_data[-1]["data"]["totalOnGridPower"])
        except Exception as e:
            _LOGGER.error("Error getting week data: %s", e)

        # Try to get house load and self-use from monthly data if available
        month_self_use_list = month_data["data"]["selfUsePower"]
        if month_self_use_list and len(month_self_use_list) > datetime.now().day - 1:
            self_use_value_today = month_self_use_list[datetime.now().day - 1]
            if self_use_value_today != "--" and self_use_value_today != "null":
                output["panel_production_consumption_today"] = extract_numeric(self_use_value_today)
    
        month_house_load_list = month_data["data"]["usePower"]
        if month_house_load_list and len(month_house_load_list) > datetime.now().day - 1:
            house_load_value_today = month_house_load_list[datetime.now().day - 1]
            if house_load_value_today != "--" and house_load_value_today != "null":
                output["house_load_today"] = extract_numeric(house_load_value_today)
        
        # Week energy sensors
        _LOGGER.debug("Getting Week's energy data")
        today = datetime.now()
        start_day_week = today - timedelta(days=today.weekday())

        days_previous_month = []
        days_current_month = []
        
        for i in range(7):
            current_day = start_day_week + timedelta(days=i)
            if current_day.month < today.month:
                days_previous_month.append(current_day.day)
            else: 
                days_current_month.append(current_day.day)

        panel_production_value_week = 0
        panel_production_consumption_value_week = 0
        house_load_value_week = 0
        battery_injection_value_week = 0
        battery_consumption_value_week = 0
        
        if days_previous_month:
            previous_month_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.PREVIOUS_MONTH)
            panel_production_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "productPower")
            panel_production_consumption_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "selfUsePower")
            house_load_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "usePower")
            battery_injection_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "chargePower")
            battery_consumption_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "dischargePower")
        
        if days_current_month:
            panel_production_value_week += self.calculate_week_energy(month_data, days_current_month, "productPower")
            panel_production_consumption_value_week += self.calculate_week_energy(month_data, days_current_month, "selfUsePower")
            house_load_value_week += self.calculate_week_energy(month_data, days_current_month, "usePower")
            battery_injection_value_week += self.calculate_week_energy(month_data, days_current_month, "chargePower")
            battery_consumption_value_week += self.calculate_week_energy(month_data, days_current_month, "dischargePower")

        output["panel_production_week"] = panel_production_value_week
        output["panel_production_consumption_week"] = panel_production_consumption_value_week
        output["house_load_week"] = house_load_value_week
        output["battery_injection_week"] = battery_injection_value_week
        output["battery_consumption_week"] = battery_consumption_value_week
        if week_data:
            output["grid_consumption_week"] = sum(extract_numeric(day["data"]["totalBuyPower"]) for day in week_data if (day["data"]["totalBuyPower"] != "--" and day["data"]["totalBuyPower"] != "null"))
            output["grid_injection_week"] = sum(extract_numeric(day["data"]["totalOnGridPower"]) for day in week_data if (day["data"]["totalOnGridPower"] != "--" and day["data"]["totalOnGridPower"] != "null"))

        # Year energy sensors
        _LOGGER.debug("Getting Years's energy data")
        year_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.YEAR)
        output["panel_production_consumption_year"] = extract_numeric(year_data["data"]["totalSelfUsePower"])
        output["house_load_year"] = extract_numeric(year_data["data"]["totalUsePower"])
        output["panel_production_year"] = extract_numeric(year_data["data"]["totalProductPower"])
        output["grid_consumption_year"] = extract_numeric(year_data["data"]["totalBuyPower"])
        output["grid_injection_year"] = extract_numeric(year_data["data"]["totalOnGridPower"])

        charge_power_list = year_data["data"]["chargePower"]
        if charge_power_list:
            total_charge_power = sum(extract_numeric(value) for value in charge_power_list if (value != "--" and value != "null"))
            output["battery_injection_year"] = total_charge_power
        
        discharge_power_list = year_data["data"]["dischargePower"]
        if discharge_power_list:
            total_discharge_power = sum(extract_numeric(value) for value in discharge_power_list if (value != "--" and value != "null"))
            output["battery_consumption_year"] = total_discharge_power
        
        use_power_list = year_data["data"]["usePower"]
        if use_power_list:
            charge_value_this_month = use_power_list[datetime.now().month - 1]
            charge_value_this_month = extract_numeric(charge_value_this_month)
            output["house_load_month"] = charge_value_this_month
        
        # Lifetime energy sensors
        _LOGGER.debug("Getting Lifetime's energy data")
        lifetime_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.LIFETIME)
        output["panel_production_lifetime"] = extract_numeric(lifetime_data["data"]["totalProductPower"])
        output["panel_production_consumption_lifetime"] = extract_numeric(lifetime_data["data"]["totalSelfUsePower"])
        output["house_load_lifetime"] = extract_numeric(lifetime_data["data"]["totalUsePower"])
        output["grid_consumption_lifetime"] = extract_numeric(lifetime_data["data"]["totalBuyPower"])
        output["grid_injection_lifetime"] = extract_numeric(lifetime_data["data"]["totalOnGridPower"])
        
        lifetime_charge_power_list = lifetime_data["data"]["chargePower"]
        if lifetime_charge_power_list:
            lifetime_total_charge_power = sum(extract_numeric(value) for value in lifetime_charge_power_list if (value != "--" and value != "--"))
            output["battery_injection_lifetime"] = lifetime_total_charge_power
        
        lifetime_discharge_power_list = lifetime_data["data"]["dischargePower"]
        if lifetime_discharge_power_list:
            lifetime_total_discharge_power = sum(extract_numeric(value) for value in lifetime_discharge_power_list if (value != "--" and value != "--"))
            output["battery_consumption_lifetime"] = lifetime_total_discharge_power
        
        
    def call_energy_balance(self, call_type: ENERGY_BALANCE_CALL_TYPE, specific_date: datetime = None):
        currentTime = datetime.now()
        timestampNow = currentTime.timestamp() * 1000
        current_day = currentTime.day
        current_month = currentTime.month
        current_year = currentTime.year
        first_day_of_month = datetime(current_year, current_month, 1)
        first_day_of_previous_month = first_day_of_month - relativedelta(months=1)
        first_day_of_year = datetime(current_year, 1, 1)

        if call_type == ENERGY_BALANCE_CALL_TYPE.MONTH:
            timestamp = first_day_of_month.timestamp() * 1000
            dateStr = first_day_of_month.strftime("%Y-%m-%d %H:%M:%S")
        elif call_type == ENERGY_BALANCE_CALL_TYPE.PREVIOUS_MONTH:
            timestamp = first_day_of_previous_month.timestamp() * 1000
            dateStr = first_day_of_previous_month.strftime("%Y-%m-%d %H:%M:%S")
            call_type = ENERGY_BALANCE_CALL_TYPE.MONTH
        elif call_type == ENERGY_BALANCE_CALL_TYPE.YEAR:
            timestamp = first_day_of_year.timestamp() * 1000
            dateStr = first_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        elif call_type == ENERGY_BALANCE_CALL_TYPE.DAY:
            if specific_date is not None:
                specific_year = specific_date.year
                specific_month = specific_date.month
                specific_day = specific_date.day
                current_day_of_year = datetime(specific_year, specific_month, specific_day)
            else:
                current_day_of_year = datetime(current_year, current_month, current_day)
            
            timestamp = current_day_of_year.timestamp() * 1000
            dateStr = current_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp = first_day_of_year.timestamp() * 1000
            dateStr = first_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        
        headers = {
            "application/json": "text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "Host": self.data_host,
            "Referer": f"https://{self.data_host}/pvmswebsite/assets/build/index.html",
            "X-Requested-With": "XMLHttpRequest",
            "Roarand": self.csrf
        }

        # Use appropriate timezone based on auth system
        timezone_offset = "0.0" if self.session_cookie_name == 'dp-session' else "8"
        timezone_str = "Europe/London" if self.session_cookie_name == 'dp-session' else "Asia/Singapore"

        params = {
             "stationDn": unquote(self.station),
             "timeDim": call_type,
             "queryTime": int(timestamp),
             "timeZone": timezone_offset,
             "timeZoneStr": timezone_str,
             "dateStr": dateStr,
             "_": int(timestampNow)
        }
         
        energy_balance_url = f"https://{self.data_host}/rest/pvms/web/station/v1/overview/energy-balance?{urlencode(params)}"
        _LOGGER.debug("Getting Energy Balance at: %s", energy_balance_url)
        energy_balance_response = self.session.get(energy_balance_url, headers=headers)
        _LOGGER.debug("Energy Balance Response: %s", energy_balance_response.text)
        try:
            energy_balance_data = energy_balance_response.json()
        except Exception as ex:
            _LOGGER.warn("Error processing Energy Balance response: JSON format invalid!")
        
        return energy_balance_data

    def get_week_data(self):
        today = datetime.now()
        start_of_week = today - timedelta(days=today.weekday())  # Segunda-feira da semana corrente
        days_to_process = []
        
        # Determinar dias a processar
        if today.weekday() == 6:  # Se for domingo
            days_to_process = [start_of_week + timedelta(days=i) for i in range(7)]
        else:  # Outros dias da semana
            days_to_process = [start_of_week + timedelta(days=i) for i in range(today.weekday() + 1)]
        
        # Obter dados para cada dia e armazenar no array
        week_data = []
        for day in days_to_process:
            day_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.DAY, specific_date=day)
            week_data.append(day_data)
            time.sleep(1)
        
        return week_data

    def calculate_week_energy(self, data, days, field):
        sum = 0
        if data["data"][field]:
            for day in days:
                value = data["data"][field][day - 1]
                if value != "--" and value != "null":
                    sum += extract_numeric(value)

        return sum

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

        if device_id.lower().replace(" ", "_") not in output:
            raise KeyError(f"'{device_id}' not found.")

        value = output[device_id.lower().replace(" ", "_")]
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
