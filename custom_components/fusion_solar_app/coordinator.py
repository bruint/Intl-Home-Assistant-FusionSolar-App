"""Fusion Solar App integration using DataUpdateCoordinator."""

from dataclasses import dataclass
from datetime import timedelta
import logging

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
        self.captcha_input = config_entry.data.get(CAPTCHA_INPUT, None)

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
        self.api = FusionSolarAPI(user=self.user, pwd=self.pwd, login_host=self.login_host, captcha_input=self.captcha_input)
        
        # Restore session cookies from config flow if available
        session_cookies = config_entry.data.get("session_cookies", {})
        if session_cookies:
            _LOGGER.info("Restoring session cookies from config flow: %s", session_cookies)
            # Set cookies on the API's session
            for name, value in session_cookies.items():
                self.api.session.cookies.set(name, value)
            # Mark as connected since we have a valid session
            self.api.connected = True
            # Note: Station data will be retrieved in first async_update_data call

    async def async_update_data(self):
        """Fetch data from API endpoint.

        This is the place to pre-process the data to lookup tables
        so entities can quickly look up their data.
        """
        try:
            if not self.api.connected:
                await self.hass.async_add_executor_job(self.api.login)
            
            # If we have a session but no station data, retrieve it now
            if self.api.connected and self.api.station is None:
                try:
                    station_data = await self.hass.async_add_executor_job(self.api.get_station_list)
                    if station_data and "data" in station_data and "list" in station_data["data"] and len(station_data["data"]["list"]) > 0:
                        self.api.station = station_data["data"]["list"][0]["dn"]
                        if self.api.battery_capacity is None or self.api.battery_capacity == 0.0:
                            self.api.battery_capacity = station_data["data"]["list"][0]["batteryCapacity"]
                        _LOGGER.info("Station retrieved from session: %s", self.api.station)
                    else:
                        _LOGGER.warning("Could not retrieve station data from session")
                except Exception as e:
                    _LOGGER.warning("Failed to retrieve station data from session: %s", e)
            
            devices = await self.hass.async_add_executor_job(self.api.get_devices)
        except APIAuthCaptchaError as err:
            _LOGGER.warning("CAPTCHA required for API access. Session may have expired.")
            # Mark as disconnected and return empty data
            self.api.connected = False
            return FusonSolarAPIData(
                controller_name=self.login_host,
                devices=[]
            )
        except APIAuthError as err:
            _LOGGER.warning("Authentication failed, attempting to re-login: %s", err)
            self.api.connected = False
            try:
                await self.hass.async_add_executor_job(self.api.login)
                devices = await self.hass.async_add_executor_job(self.api.get_devices)
            except APIAuthCaptchaError:
                _LOGGER.warning("CAPTCHA required for re-login. Integration will retry on next update.")
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
