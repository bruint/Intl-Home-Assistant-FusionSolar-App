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
        
        _LOGGER.info("=== CAPTCHA STEP: Entry point ===")
        _LOGGER.info("CAPTCHA Step - user_input is None: %s", user_input is None)
        if user_input is not None:
            _LOGGER.info("CAPTCHA Step - Received user_input with keys: %s", list(user_input.keys()))
            _LOGGER.info("CAPTCHA Step - CAPTCHA code in input: '%s'", user_input.get(CAPTCHA_INPUT, "NOT PROVIDED"))
        
        if user_input is not None:
            _LOGGER.warning("=== CAPTCHA STEP: Processing user input ===")
            _LOGGER.warning("CAPTCHA Step - Credentials step called with user_input: %s", user_input)
            
            # Combine domain and credentials
            full_data = {**domain_data, **user_input}
            
            try:
                # Try to login with the provided credentials and CAPTCHA
                # Reuse the same API instance that fetched the CAPTCHA to maintain session
                captcha_code = user_input.get(CAPTCHA_INPUT, "").strip()
                _LOGGER.warning("=== CAPTCHA STEP: Preparing login attempt ===")
                _LOGGER.warning("CAPTCHA Step - Extracted CAPTCHA code from user input: '%s' (length: %d)", captcha_code, len(captcha_code))
                _LOGGER.warning("CAPTCHA Step - Has stored API instance: %s", hasattr(self, '_captcha_api_instance') and self._captcha_api_instance is not None)
                
                if hasattr(self, '_captcha_api_instance') and self._captcha_api_instance:
                    _LOGGER.info("CAPTCHA Step - Reusing stored API instance")
                    api = self._captcha_api_instance
                    old_captcha = api.captcha_input
                    api.user = user_input[CONF_USERNAME]
                    api.pwd = user_input[CONF_PASSWORD]
                    # Always use the CAPTCHA code from the current user input, not any stale value
                    api.captcha_input = captcha_code
                    _LOGGER.info("CAPTCHA Step - API instance old captcha_input: '%s'", old_captcha)
                    _LOGGER.info("CAPTCHA Step - API instance new captcha_input: '%s'", api.captcha_input)
                    _LOGGER.info("CAPTCHA Step - Reusing API instance with session cookies: %s", api._get_cookies_safe())
                else:
                    _LOGGER.info("CAPTCHA Step - Creating new API instance (no stored instance)")
                    # Fallback: create new API instance if no stored instance
                    api = FusionSolarAPI(
                        user_input[CONF_USERNAME], 
                        user_input[CONF_PASSWORD], 
                        domain, 
                        captcha_code
                    )
                    _LOGGER.info("CAPTCHA Step - New API instance created with captcha_input: '%s'", api.captcha_input)
                
                _LOGGER.info("=== CAPTCHA STEP: Calling login API ===")
                _LOGGER.info("CAPTCHA Step - Login attempt - domain: %s, username: %s, captcha: '%s'", domain, user_input[CONF_USERNAME], captcha_code)
                _LOGGER.info("CAPTCHA Step - API instance captcha_input before login: '%s'", api.captcha_input)
                await self.hass.async_add_executor_job(api.login)
                _LOGGER.info("=== CAPTCHA STEP: Login successful ===")
                
                # If we get here, login was successful
                info = {"title": f"Fusion Solar App Integration"}
                await self.async_set_unique_id(info.get("title"))
                self._abort_if_unique_id_configured()
                
                # Store session cookies and data_host in config data for coordinator to use
                session_cookies = api._get_cookies_safe()
                full_data["session_cookies"] = session_cookies
                full_data["data_host"] = api.data_host
                # Don't store CAPTCHA input - CAPTCHA codes are single-use and shouldn't be stored
                # Remove it if it was in the input data
                if CAPTCHA_INPUT in full_data:
                    _LOGGER.info("CAPTCHA Step - Removing CAPTCHA_INPUT from config data (single-use codes shouldn't be stored)")
                    del full_data[CAPTCHA_INPUT]
                _LOGGER.error("CAPTCHA Debug - Storing session cookies in config: %s", session_cookies)
                _LOGGER.info("Storing data_host in config: %s", api.data_host)
                
                return self.async_create_entry(title=info["title"], data=full_data)
                
            except APIAuthCaptchaError:
                _LOGGER.info("=== CAPTCHA STEP: Login failed - CAPTCHA required ===")
                _LOGGER.info("CAPTCHA Step - APIAuthCaptchaError caught, CAPTCHA still required")
                errors["base"] = "captcha_required"
                # Clear the old API instance to force a fresh CAPTCHA fetch
                if hasattr(self, '_captcha_api_instance'):
                    _LOGGER.info("CAPTCHA Step - Clearing stored API instance to force fresh CAPTCHA")
                    delattr(self, '_captcha_api_instance')
            except APIAuthError as e:
                _LOGGER.info("=== CAPTCHA STEP: Login failed - APIAuthError ===")
                _LOGGER.info("CAPTCHA Step - APIAuthError: %s", str(e))
                if "Incorrect CAPTCHA code" in str(e) or "Incorrect CAPTCHA" in str(e):
                    _LOGGER.info("CAPTCHA Step - Error indicates incorrect CAPTCHA code")
                    _LOGGER.info("CAPTCHA Step - CAPTCHA code that was used: '%s'", captcha_code)
                    errors["base"] = "captcha_incorrect"
                    # Clear the old API instance to force a fresh CAPTCHA fetch
                    if hasattr(self, '_captcha_api_instance'):
                        _LOGGER.info("CAPTCHA Step - Clearing stored API instance to force fresh CAPTCHA")
                        delattr(self, '_captcha_api_instance')
                else:
                    _LOGGER.info("CAPTCHA Step - Error indicates invalid credentials (not CAPTCHA)")
                    errors["base"] = "invalid_auth"
            except APIConnectionError:
                _LOGGER.info("=== CAPTCHA STEP: Login failed - Connection error ===")
                errors["base"] = "cannot_connect"
            except Exception as e:
                _LOGGER.info("=== CAPTCHA STEP: Login failed - Unexpected error ===")
                _LOGGER.info("CAPTCHA Step - Unexpected error: %s", e)
                _LOGGER.exception("CAPTCHA Step - Full exception traceback:")
                errors["base"] = "unknown"
        
        # Get CAPTCHA image for display
        # Always fetch a fresh CAPTCHA image - don't reuse old instances
        _LOGGER.warning("=== CAPTCHA STEP: Fetching CAPTCHA image ===")
        _LOGGER.warning("CAPTCHA Step - About to fetch CAPTCHA image for domain: %s", domain)
        _LOGGER.warning("CAPTCHA Step - Has stored API instance before fetch: %s", hasattr(self, '_captcha_api_instance') and self._captcha_api_instance is not None)
        
        captcha_img = ""
        api_instance = None
        try:
            # Create a fresh API instance for fetching CAPTCHA
            # This ensures we get a new CAPTCHA image and don't reuse stale state
            _LOGGER.warning("CAPTCHA Step - Creating fresh API instance for CAPTCHA fetch")
            api_instance = FusionSolarAPI("", "", domain, None)
            api_instance.captcha_input = None  # Clear any old CAPTCHA input
            _LOGGER.warning("CAPTCHA Step - API instance created, captcha_input cleared to: %s", api_instance.captcha_input)
            _LOGGER.warning("CAPTCHA Step - Calling set_captcha_img()")
            await self.hass.async_add_executor_job(api_instance.set_captcha_img)
            captcha_img = api_instance.captcha_img
            _LOGGER.warning("CAPTCHA Step - CAPTCHA image fetch result: %s", "SUCCESS" if captcha_img else "FAILED")
            if captcha_img:
                _LOGGER.warning("CAPTCHA Step - Image length: %d characters", len(captcha_img))
                _LOGGER.warning("CAPTCHA Step - Image starts with: %s", captcha_img[:50] if len(captcha_img) > 50 else captcha_img)
                _LOGGER.warning("CAPTCHA Step - Image is base64 data URL: %s", captcha_img.startswith("data:image"))
            else:
                _LOGGER.error("CAPTCHA Step - No image data received - captcha_img is empty or None")
        except Exception as err:
            _LOGGER.error("CAPTCHA Step - Failed to get CAPTCHA image: %s", err)
            _LOGGER.exception("CAPTCHA Step - Exception traceback:")
            captcha_img = ""
        
        # Show credentials form with CAPTCHA
        _LOGGER.warning("=== CAPTCHA STEP: Preparing form display ===")
        if captcha_img:
            # Use exact same format as the old working version
            captcha_html = '<img id="fusion_solar_app_security_captcha" src="' + captcha_img + '"/>'
            _LOGGER.warning("CAPTCHA Step - CAPTCHA image available, creating HTML")
            _LOGGER.warning("CAPTCHA Step - Full HTML length: %d characters", len(captcha_html))
        else:
            captcha_html = '<p><strong>CAPTCHA Image Failed to Load</strong><br/>Please try refreshing the page or check your network connection.</p>'
            _LOGGER.error("CAPTCHA Step - No CAPTCHA image, showing error message")
        
        _LOGGER.warning("CAPTCHA Step - HTML preview (first 200 chars): %s", captcha_html[:200] + "..." if len(captcha_html) > 200 else captcha_html)
        _LOGGER.warning("CAPTCHA Step - Domain for placeholder: %s", domain)
        
        # Store the API instance for reuse in login attempt
        # This maintains the session cookies from the CAPTCHA fetch
        _LOGGER.warning("CAPTCHA Step - Storing API instance for reuse in login attempt")
        _LOGGER.warning("CAPTCHA Step - API instance captcha_input when storing: %s", api_instance.captcha_input if api_instance else "N/A")
        self._captcha_api_instance = api_instance
        
        description_placeholders = {"captcha_img": captcha_html, "domain": domain}
        _LOGGER.warning("CAPTCHA Step - description_placeholders keys: %s", list(description_placeholders.keys()))
        _LOGGER.warning("CAPTCHA Step - description_placeholders captcha_img length: %d", len(description_placeholders["captcha_img"]))
        _LOGGER.warning("=== CAPTCHA STEP: Showing form to user ===")
        
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
            description_placeholders=description_placeholders,
            errors=errors,
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
            _LOGGER.info("Reconfigure step - attempting login with host: %s", user_input[FUSION_SOLAR_HOST])
            try:
                # Try to login with the provided credentials
                api = FusionSolarAPI(
                    user_input[CONF_USERNAME], 
                    user_input[CONF_PASSWORD], 
                    user_input[FUSION_SOLAR_HOST], 
                    ""
                )
                _LOGGER.info("Reconfigure - calling login API")
                await self.hass.async_add_executor_job(api.login)
                _LOGGER.info("Reconfigure - login successful")
                
                # If we get here, login was successful
                # Store updated session cookies and data_host
                session_cookies = api._get_cookies_safe()
                updated_data = {**config_entry.data, **user_input}
                updated_data["session_cookies"] = session_cookies
                updated_data["data_host"] = api.data_host
                _LOGGER.info("Reconfigure - storing updated data_host: %s", api.data_host)
                
                return self.async_update_reload_and_abort(
                    config_entry,
                    unique_id=config_entry.unique_id,
                    data=updated_data,
                    reason="reconfigure_successful",
                )
            except APIAuthCaptchaError:
                _LOGGER.warning("Reconfigure - CAPTCHA required, redirecting to CAPTCHA step")
                _LOGGER.warning("Reconfigure - Storing user_input as _input_data for CAPTCHA step")
                # Store the user input so async_step_captcha can access the domain
                self._input_data = user_input  # Store the original user data
                # Clear any existing CAPTCHA API instance to force fresh fetch
                if hasattr(self, '_captcha_api_instance'):
                    del self._captcha_api_instance
                return await self.async_step_captcha()
            except APIAuthError as auth_err:
                _LOGGER.error("Authentication error during reconfigure: %s", auth_err)
                import traceback
                _LOGGER.error("Traceback: %s", traceback.format_exc())
                errors["base"] = "invalid_auth"
            except APIConnectionError as conn_err:
                _LOGGER.error("Connection error during reconfigure: %s", conn_err)
                import traceback
                _LOGGER.error("Traceback: %s", traceback.format_exc())
                errors["base"] = "cannot_connect"
            except Exception as ex:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during reconfigure: %s", ex)
                _LOGGER.error("Exception type: %s", type(ex).__name__)
                import traceback
                _LOGGER.error("Full traceback: %s", traceback.format_exc())
                errors["base"] = "unknown"
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
        super().__init__()
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
