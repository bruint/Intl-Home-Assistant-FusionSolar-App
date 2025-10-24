"""Config flow for Fusion Solar App Integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import (
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError

from .api import FusionSolarAPI, APIAuthError, APIConnectionError, APIAuthCaptchaError
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN, MIN_SCAN_INTERVAL, FUSION_SOLAR_HOST, CAPTCHA_INPUT


_LOGGER = logging.getLogger(__name__)

# TODO adjust the data schema to the data that you need
STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME, description={"suggested_value": ""}): str,
        vol.Required(CONF_PASSWORD, description={"suggested_value": ""}): str,
        vol.Required(FUSION_SOLAR_HOST, description={"suggested_value": "eu5.fusionsolar.huawei.com"}): str
    }
)

STEP_CAPTCHA_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CAPTCHA_INPUT): str,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    api = FusionSolarAPI(data[CONF_USERNAME], data[CONF_PASSWORD], data[FUSION_SOLAR_HOST], data.get(CAPTCHA_INPUT, None))
    try:
        await hass.async_add_executor_job(api.login)
        # If you cannot connect, raise CannotConnect
        # If the authentication is wrong, raise InvalidAuth
    except APIAuthError as err:
        raise InvalidAuth from err
    except APIAuthCaptchaError as err:
        raise InvalidCaptcha from err
    except APIConnectionError as err:
        raise CannotConnect from err
    return {"title": f"Fusion Solar App Integration"}


class FusionSolarConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Fusion Solar App Integration."""

    VERSION = 1
    _input_data: dict[str, Any]

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        # Remove this method and the FusionSolarConfigFlow class
        # if you do not want any options for your integration.
        return FusionSolarOptionsFlowHandler(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        # Called when you initiate adding an integration via the UI
        errors: dict[str, str] = {}

        if user_input is not None:
            # The form has been filled in and submitted, so process the data provided.
            try:
                # Validate that the setup data is valid and if not handle errors.
                # The errors["base"] values match the values in your strings.json and translation files.
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except InvalidCaptcha:
                _LOGGER.exception("Captcha failed, redirecting to Captcha screen")
                self._input_data = user_input  # Store the original user data
                return await self.async_step_captcha(user_input)
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

            if "base" not in errors:
                # Validation was successful, so create a unique id for this instance of your integration
                # and create the config entry.
                await self.async_set_unique_id(info.get("title"))
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=info["title"], data=user_input)

        # Show initial form.
        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Add reconfigure step to allow to reconfigure a config entry."""
        # This method displays a reconfigure option in the integration and is
        # different to options.
        # It can be used to reconfigure any of the data submitted when first installed.
        # This is optional and can be removed if you do not want to allow reconfiguration.
        errors: dict[str, str] = {}
        config_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )

        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except InvalidCaptcha:
                _LOGGER.exception("Captcha failed, redirecting to Captcha screen")
                self._input_data = user_input  # Store the original user data
                return await self.async_step_captcha(user_input)
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_update_reload_and_abort(
                    config_entry,
                    unique_id=config_entry.unique_id,
                    data={**config_entry.data, **user_input},
                    reason="reconfigure_successful",
                )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME, default=config_entry.data[CONF_USERNAME]): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(FUSION_SOLAR_HOST, default=config_entry.data[FUSION_SOLAR_HOST]): str,
                }
            ),
            errors=errors,
        )
    
    async def async_step_captcha(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        
        # Get the original user data from the flow context
        original_data = self._input_data if hasattr(self, '_input_data') else user_input
        
        if user_input is not None:
            captcha_response = user_input.get(CAPTCHA_INPUT, "").strip()
    
            if not captcha_response:
                _LOGGER.warning("No Captcha code filled.")
                errors["base"] = "captcha_required"
            else:
                _LOGGER.debug("Validating Login with CAPTCHA: %s", captcha_response)
                _LOGGER.info("CAPTCHA Debug - Input: '%s', Length: %d", captcha_response, len(captcha_response))
                # Create API with the CAPTCHA input
                api = FusionSolarAPI(original_data[CONF_USERNAME], original_data[CONF_PASSWORD], original_data[FUSION_SOLAR_HOST], captcha_response)
                try:
                    _LOGGER.info("CAPTCHA Debug - Attempting login with CAPTCHA: %s", captcha_response)
                    await self.hass.async_add_executor_job(api.login)
                    _LOGGER.info("CAPTCHA Debug - Login successful!")
                    # If login successful, create the config entry
                    info = {"title": f"Fusion Solar App Integration"}
                    await self.async_set_unique_id(info.get("title"))
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title=info["title"], data=original_data)
                except APIAuthError as err:
                    _LOGGER.error("Login failed with CAPTCHA: %s", err)
                    _LOGGER.info("CAPTCHA Debug - Auth error with CAPTCHA: %s", captcha_response)
                    errors["base"] = "invalid_auth"
                except APIAuthCaptchaError as err:
                    _LOGGER.error("CAPTCHA still required: %s", err)
                    _LOGGER.info("CAPTCHA Debug - CAPTCHA error with input: %s", captcha_response)
                    errors["base"] = "captcha_required"
                except APIConnectionError as err:
                    _LOGGER.error("Connection error: %s", err)
                    errors["base"] = "cannot_connect"
                except Exception as err:
                    _LOGGER.exception("Unexpected exception: %s", err)
                    # Check if it's a network connectivity issue
                    if "Network unreachable" in str(err) or "Connection refused" in str(err):
                        errors["base"] = "cannot_connect"
                    else:
                        errors["base"] = "unknown"
        
        # Get CAPTCHA image for display (only if no user input yet or if there are errors)
        if user_input is None or errors:
            try:
                api = FusionSolarAPI(original_data[CONF_USERNAME], original_data[CONF_PASSWORD], original_data[FUSION_SOLAR_HOST], None)
                _LOGGER.debug("Obtaining Captcha image...")
                await self.hass.async_add_executor_job(api.set_captcha_img)
                captcha_img = api.captcha_img
                _LOGGER.debug("Got most recent Captcha image...")
            except Exception as err:
                _LOGGER.error("Failed to get CAPTCHA image: %s", err)
                captcha_img = ""
                if not errors:  # Only add error if there wasn't already an error
                    if "Network unreachable" in str(err) or "Connection refused" in str(err):
                        errors["base"] = "cannot_connect"
                    else:
                        errors["base"] = "unknown"
        else:
            # If no errors, we shouldn't reach here, but just in case
            captcha_img = ""
    
        return self.async_show_form(
            step_id="captcha",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME, default=original_data[CONF_USERNAME]): str,
                    vol.Required(CONF_PASSWORD, default=original_data[CONF_PASSWORD]): str,
                    vol.Required(FUSION_SOLAR_HOST, default=original_data[FUSION_SOLAR_HOST]): str,
                    vol.Required(CAPTCHA_INPUT): str,
                }
            ),
            description_placeholders={"captcha_img": '<img id="fusion_solar_app_security_captcha" src="' + captcha_img + '"/>'},
            errors=errors,
        )


class FusionSolarOptionsFlowHandler(OptionsFlow):
    """Handles the options flow."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry
        self.options = dict(config_entry.options)

    async def async_step_init(self, user_input=None):
        """Handle options flow."""
        if user_input is not None:
            options = self.config_entry.options | user_input
            return self.async_create_entry(title="", data=options)

        # It is recommended to prepopulate options fields with default values if available.
        # These will be the same default values you use on your coordinator for setting variable values
        # if the option has not been set.
        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=self.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): (vol.All(vol.Coerce(int), vol.Clamp(min=MIN_SCAN_INTERVAL))),
            }
        )

        return self.async_show_form(step_id="init", data_schema=data_schema)


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""

class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""

class InvalidCaptcha(HomeAssistantError):
    """Error to indicate there is invalid captcha."""
