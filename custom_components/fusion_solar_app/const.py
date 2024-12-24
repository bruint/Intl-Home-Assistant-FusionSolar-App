"""Constants for the Integration Fusion Solar App."""

DOMAIN = "fusion_solar_app"

DEFAULT_SCAN_INTERVAL = 60
MIN_SCAN_INTERVAL = 10
STATION_KEY = "station"
LOGIN_HOST = "login_host"
DATA_HOST = "data_host"
PUBKEY_URL = "/unisso/pubkey"
LOGIN_VALIDATE_USER_URL = "/unisso/v3/validateUser.action"
LOGIN_HEADERS_1_STEP_REFERER = "/unisso/login.action"
LOGIN_HEADERS_2_STEP_REFERER = "/pvmswebsite/loginCustomize.html"
DATA_URL = "/rest/pvms/web/station/v2/overview/energy-flow"
