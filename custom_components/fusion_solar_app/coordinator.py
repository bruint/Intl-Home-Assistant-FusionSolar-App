"""Fusion Solar App integration using DataUpdateCoordinator."""

from dataclasses import dataclass
from datetime import timedelta
import logging
import requests

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
)
from homeassistant.core import DOMAIN, HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import FusionSolarAPI, APIAuthError, APIAuthCaptchaError, Device, DeviceType
from .const import DEFAULT_SCAN_INTERVAL, FUSION_SOLAR_HOST, CAPTCHA_INPUT

_LOGGER = logging.getLogger(__name__)


@dataclass
class FusonSolarAPIData:
    """Class to hold api data."""

    controller_name: str
    devices: list[Device]
    #device


class FusionSolarCoordinator(DataUpdateCoordinator):
    """My coordinator."""

    data: FusonSolarAPIData

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry) -> None:
        """Initialize coordinator."""

        # Set variables from values entered in config flow setup
        self.user = config_entry.data[CONF_USERNAME]
        self.pwd = config_entry.data[CONF_PASSWORD]
        self.login_host = config_entry.data[FUSION_SOLAR_HOST]
        # Don't use stored CAPTCHA input - CAPTCHA codes are single-use and shouldn't be reused
        # The coordinator should never use CAPTCHA codes for automatic login
        self.captcha_input = None

        # set variables from options.  You need a default here incase options have not been set
        self.poll_interval = config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )

        self.lastAuthentication = None

        # Initialise DataUpdateCoordinator
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} ({config_entry.unique_id})",
            # Method to call on every update interval.
            update_method=self.async_update_data,
            # Polling interval. Will only be polled if there are subscribers.
            # Using config option here but you can just use a value.
            update_interval=timedelta(seconds=self.poll_interval),
        )

        # Initialise your api here
        # Never pass CAPTCHA input to the coordinator's API instance
        # CAPTCHA codes are single-use and only valid during config flow
        self.api = FusionSolarAPI(user=self.user, pwd=self.pwd, login_host=self.login_host, captcha_input=None)
        
        # Restore session cookies from config flow if available
        session_cookies = config_entry.data.get("session_cookies", {})
        if session_cookies:
            _LOGGER.info("Restoring session cookies from config flow: %s", session_cookies)
            # Reset the cookie jar entirely to avoid duplicate-name cookies across domains/paths
            try:
                self.api.session.cookies = requests.cookies.RequestsCookieJar()
                for name, value in session_cookies.items():
                    # Set raw first; we'll normalize sensitive ones (like JSESSIONID) below
                    self.api.session.cookies.set(name, value)

                # Extra hardening: ensure only ONE JSESSIONID remains and is scoped to the login host
                try:
                    jsession_values = []
                    for c in list(self.api.session.cookies):
                        if c.name == "JSESSIONID":
                            jsession_values.append((c.domain, c.path, c.value))
                            # Clear all JSESSIONID variants
                            try:
                                self.api.session.cookies.clear(c.domain, c.path, c.name)
                            except Exception:
                                # Fallback clear by name if domain/path unknown
                                try:
                                    self.api.session.cookies.clear(name=c.name)
                                except Exception:
                                    pass
                    if jsession_values:
                        # Choose the most recent value provided in session_cookies
                        chosen_value = session_cookies.get("JSESSIONID", jsession_values[-1][2])
                        # Re-set a single normalized cookie bound to the login host
                        self.api.session.cookies.set(
                            "JSESSIONID",
                            chosen_value,
                            domain=self.login_host,
                            path="/",
                        )
                        _LOGGER.info(
                            "Normalized JSESSIONID. Before=%s After=%s",
                            jsession_values,
                            [(c.domain, c.path, c.value) for c in self.api.session.cookies if c.name == "JSESSIONID"],
                        )
                except Exception as norm_err:
                    _LOGGER.warning("Failed to normalize JSESSIONID cookie: %s", norm_err)

                # Log final cookie jar state for diagnostics
                _LOGGER.info(
                    "Final restored cookies: %s",
                    [(c.name, c.domain, c.path, c.value[:8] + "…") for c in self.api.session.cookies],
                )
            except Exception as e:
                _LOGGER.warning("Failed to rebuild session cookies: %s", e)
            
            # Restore data_host from config if available
            data_host = config_entry.data.get("data_host")
            if data_host:
                self.api.data_host = data_host
                _LOGGER.info("Restored data_host from config: %s", data_host)
                
                # Don't validate synchronously in __init__ - do it in async_update_data
                # This avoids blocking the coordinator initialization
                _LOGGER.info("Session cookies and data_host restored, will validate on first update")
            else:
                # If data_host is not in config, don't restore cookies - force fresh login
                # This handles old configs that don't have data_host stored
                _LOGGER.warning("data_host not found in config - cookies may be invalid. Will attempt fresh login.")
                # Clear the restored cookies and mark as not connected to force fresh login
                self.api.session.cookies = requests.cookies.RequestsCookieJar()
                self.api.connected = False

    async def async_update_data(self):
        """Fetch data from API endpoint.

        This is the place to pre-process the data to lookup tables
        so entities can quickly look up their data.
        """
        _LOGGER.info("Coordinator update started - connected: %s, station: %s", self.api.connected, self.api.station)
        try:
            if not self.api.connected:
                # First, try to validate/refresh the existing session before attempting login
                # This avoids unnecessary CAPTCHA requirements if the session is still valid
                if self.api.data_host and self.api.session.cookies:
                    _LOGGER.info("Not connected, but have data_host and cookies - attempting to refresh session")
                    try:
                        await self.hass.async_add_executor_job(self.api.refresh_csrf)
                        # If refresh_csrf succeeds, session is valid
                        self.api.connected = True
                        _LOGGER.info("Session refreshed successfully - no login needed")
                    except Exception as refresh_err:
                        _LOGGER.warning("Session refresh failed: %s. Will attempt login.", refresh_err)
                        # Session refresh failed, need to login (but this will require CAPTCHA)
                        _LOGGER.warning("Login will be required, but CAPTCHA is needed. Integration will be unavailable until reconfigured.")
                        raise APIAuthCaptchaError("Session expired and login requires CAPTCHA")
                
                if not self.api.connected:
                    _LOGGER.info("Not connected and no valid session, attempting login")
                    # Ensure CAPTCHA input is cleared - coordinator should never use stored CAPTCHA codes
                    self.api.captcha_input = None
                    _LOGGER.info("Coordinator - Cleared CAPTCHA input before login attempt (captcha_input: %s)", self.api.captcha_input)
                    await self.hass.async_add_executor_job(self.api.login)
                    _LOGGER.info("Login completed - connected: %s", self.api.connected)
            
            # If we have a session but no station data, retrieve it now
            if self.api.connected and self.api.station is None:
                _LOGGER.info("Connected but no station, retrieving station data")
                try:
                    station_data = await self.hass.async_add_executor_job(self.api.get_station_list)
                    _LOGGER.debug("Station data retrieved: %s", station_data)
                    if station_data and "data" in station_data and "list" in station_data["data"] and len(station_data["data"]["list"]) > 0:
                        self.api.station = station_data["data"]["list"][0]["dn"]
                        _LOGGER.info("Station retrieved from session: %s", self.api.station)
                    else:
                        _LOGGER.warning("Could not retrieve station data from session")
                        _LOGGER.debug("Station data structure: %s", station_data)
                except Exception as e:
                    _LOGGER.error("Failed to retrieve station data from session: %s", e)
                    import traceback
                    _LOGGER.error("Traceback: %s", traceback.format_exc())
            
            _LOGGER.info("Getting devices from API")
            devices = await self.hass.async_add_executor_job(self.api.get_devices)
            _LOGGER.info("Retrieved %d devices", len(devices))
        except APIAuthCaptchaError as err:
            _LOGGER.warning("CAPTCHA required for API access. Session may have expired.")
            # Mark as disconnected and return empty data
            self.api.connected = False
            return FusonSolarAPIData(
                controller_name=self.login_host,
                devices=[]
            )
        except APIAuthError as err:
            _LOGGER.warning("Authentication failed: %s", err)
            # Check if this is a CAPTCHA-related error
            if "CAPTCHA" in str(err) or "captcha" in str(err).lower():
                _LOGGER.warning("CAPTCHA required - cannot auto-login. User must reconfigure integration.")
                self.api.connected = False
                return FusonSolarAPIData(
                    controller_name=self.login_host,
                    devices=[]
                )
            
            # For other auth errors, try one re-login attempt
            _LOGGER.warning("Attempting one re-login attempt")
            self.api.connected = False
            # Clear any stale CAPTCHA input before retry
            self.api.captcha_input = None
            _LOGGER.info("Coordinator - Cleared CAPTCHA input before re-login (captcha_input: %s)", self.api.captcha_input)
            try:
                await self.hass.async_add_executor_job(self.api.login)
                devices = await self.hass.async_add_executor_job(self.api.get_devices)
            except APIAuthCaptchaError:
                _LOGGER.warning("CAPTCHA required for re-login. Integration will retry on next update.")
                return FusonSolarAPIData(
                    controller_name=self.login_host,
                    devices=[]
                )
            except APIAuthError as retry_err:
                _LOGGER.warning("Re-login also failed: %s. User may need to reconfigure.", retry_err)
                return FusonSolarAPIData(
                    controller_name=self.login_host,
                    devices=[]
                )
        except Exception as err:
            # This will show entities as unavailable by raising UpdateFailed exception
            _LOGGER.error(err)
            raise UpdateFailed(f"Error communicating with API: {err}") from err

        # What is returned here is stored in self.data by the DataUpdateCoordinator
        return FusonSolarAPIData(self.api.controller_name, devices)

    def get_device_by_id(
        self, device_type: DeviceType, device_id: int
    ) -> Device | None:
        """Return device by device id."""
        # Called by the binary sensors and sensors to get their updated data from self.data
        try:
            return [
                device
                for device in self.data.devices
                if device.device_type == device_type and device.device_id == device_id
            ][0]
        except IndexError:
            return None
