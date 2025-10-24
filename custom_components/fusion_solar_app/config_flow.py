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

# Step 1: Domain only
STEP_DOMAIN_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(FUSION_SOLAR_HOST, description={"suggested_value": "sg5.fusionsolar.huawei.com"}): str
    }
)


class FusionSolarConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Fusion Solar App Integration."""

    VERSION = 1
    _input_data: dict[str, Any]

    def __init__(self):
        """Initialize the config flow."""
        super().__init__()
        self._input_data = {}

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
        """Handle the initial step - collect domain only."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # Store the domain and move to credentials step
            self._input_data = user_input
            _LOGGER.error("CAPTCHA Debug - Domain collected: %s", user_input[FUSION_SOLAR_HOST])
            return await self.async_step_captcha()

        # Show domain form
        return self.async_show_form(
            step_id="user", 
            data_schema=STEP_DOMAIN_DATA_SCHEMA, 
            errors=errors
        )

    async def async_step_captcha(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the credentials step - username, password, and CAPTCHA."""
        errors: dict[str, str] = {}
        
        # Get the domain from the previous step
        domain_data = self._input_data if hasattr(self, '_input_data') else {}
        domain = domain_data.get(FUSION_SOLAR_HOST, "")
        
        if user_input is not None:
            _LOGGER.error("CAPTCHA Debug - Credentials step called with user_input: %s", user_input)
            
            # Combine domain and credentials
            full_data = {**domain_data, **user_input}
            
            try:
                # Try to login with the provided credentials and CAPTCHA
                # Reuse the same API instance that fetched the CAPTCHA to maintain session
                if hasattr(self, '_captcha_api_instance') and self._captcha_api_instance:
                    api = self._captcha_api_instance
                    api.user = user_input[CONF_USERNAME]
                    api.pwd = user_input[CONF_PASSWORD]
                    api.captcha_input = user_input.get(CAPTCHA_INPUT, "")
                    _LOGGER.error("CAPTCHA Debug - Reusing API instance with session cookies: %s", dict(api.session.cookies))
                else:
                    # Fallback: create new API instance if no stored instance
                    api = FusionSolarAPI(
                        user_input[CONF_USERNAME], 
                        user_input[CONF_PASSWORD], 
                        domain, 
                        user_input.get(CAPTCHA_INPUT, "")
                    )
                    _LOGGER.error("CAPTCHA Debug - Created new API instance (no stored instance)")
                
                _LOGGER.error("CAPTCHA Debug - Attempting login with domain: %s, username: %s", domain, user_input[CONF_USERNAME])
                await self.hass.async_add_executor_job(api.login)
                
                # If we get here, login was successful
                info = {"title": f"Fusion Solar App Integration"}
                await self.async_set_unique_id(info.get("title"))
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=info["title"], data=full_data)
                
            except APIAuthCaptchaError:
                _LOGGER.error("CAPTCHA Debug - CAPTCHA still required")
                errors["base"] = "captcha_required"
            except APIAuthError as e:
                if "Incorrect CAPTCHA code" in str(e):
                    _LOGGER.error("CAPTCHA Debug - Incorrect CAPTCHA provided")
                    errors["base"] = "captcha_incorrect"
                else:
                    _LOGGER.error("CAPTCHA Debug - Invalid credentials")
                    errors["base"] = "invalid_auth"
            except APIConnectionError:
                _LOGGER.error("CAPTCHA Debug - Connection error")
                errors["base"] = "cannot_connect"
            except Exception as e:
                _LOGGER.error("CAPTCHA Debug - Unexpected error: %s", e)
                errors["base"] = "unknown"
        
        # Get CAPTCHA image for display
        captcha_img = ""
        api_instance = None
        try:
            api_instance = FusionSolarAPI("", "", domain, None)
            _LOGGER.error("CAPTCHA Debug - Getting CAPTCHA image for domain: %s", domain)
            await self.hass.async_add_executor_job(api_instance.set_captcha_img)
            captcha_img = api_instance.captcha_img
            _LOGGER.error("CAPTCHA Debug - CAPTCHA image obtained: %s", "SUCCESS" if captcha_img else "FAILED")
            if captcha_img:
                _LOGGER.error("CAPTCHA Debug - Image length: %d characters", len(captcha_img))
                _LOGGER.error("CAPTCHA Debug - Image starts with: %s", captcha_img[:50] if len(captcha_img) > 50 else captcha_img)
            else:
                _LOGGER.error("CAPTCHA Debug - No image data received")
        except Exception as err:
            _LOGGER.error("CAPTCHA Debug - Failed to get CAPTCHA image: %s", err)
            captcha_img = ""
        
        # Show credentials form with CAPTCHA
        if captcha_img:
            # Use exact same format as the old working version
            captcha_html = '<img id="fusion_solar_app_security_captcha" src="' + captcha_img + '"/>'
        else:
            captcha_html = '<p><strong>CAPTCHA Image Failed to Load</strong><br/>Please try refreshing the page or check your network connection.</p>'
        
        _LOGGER.error("CAPTCHA Debug - HTML to display: %s", captcha_html[:100] + "..." if len(captcha_html) > 100 else captcha_html)
        
        # Store the API instance for reuse in login attempt
        self._captcha_api_instance = api_instance
        
        return self.async_show_form(
            step_id="captcha",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME, default=""): str,
                    vol.Required(CONF_PASSWORD, default=""): str,
                    vol.Required(FUSION_SOLAR_HOST, default=domain): str,
                    vol.Required(CAPTCHA_INPUT): str,
                }
            ),
            description_placeholders={"captcha_img": captcha_html},
            errors=errors,
            description=f"Enter your credentials for {domain}\n\n{captcha_html}",
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
                # Try to login with the provided credentials
                api = FusionSolarAPI(
                    user_input[CONF_USERNAME], 
                    user_input[CONF_PASSWORD], 
                    user_input[FUSION_SOLAR_HOST], 
                    ""
                )
                await self.hass.async_add_executor_job(api.login)
                
                # If we get here, login was successful
                info = {"title": f"Fusion Solar App Integration"}
            except APIAuthCaptchaError:
                _LOGGER.exception("Captcha failed, redirecting to Credentials screen")
                self._input_data = user_input  # Store the original user data
                return await self.async_step_captcha()
            except APIAuthError:
                errors["base"] = "invalid_auth"
            except APIConnectionError:
                errors["base"] = "cannot_connect"
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
