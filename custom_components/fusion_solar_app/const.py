"""Constants for the Integration Fusion Solar App."""

DOMAIN = "fusion_solar_app"

DEFAULT_SCAN_INTERVAL = 60
MIN_SCAN_INTERVAL = 10
STATION_KEY = "station"
PUBKEY_URL = "https://eu5.fusionsolar.huawei.com/unisso/pubkey"
LOGIN_REDIRECT_URL = "https://eu5.fusionsolar.huawei.com"
LOGIN_VALIDATE_USER_URL = "https://eu5.fusionsolar.huawei.com/unisso/v3/validateUser.action"
LOGIN_HEADERS_HOST = "eu5.fusionsolar.huawei.com"
LOGIN_HEADERS_ORIGIN = "https://eu5.fusionsolar.huawei.com"
LOGIN_HEADERS_1_STEP_REFERER = "https://eu5.fusionsolar.huawei.com/unisso/login.action"
LOGIN_HEADERS_2_STEP_REFERER = "https://eu5.fusionsolar.huawei.com/pvmswebsite/loginCustomize.html"
DATA_URL = "https://uni001eu5.fusionsolar.huawei.com/rest/pvms/web/station/v2/overview/energy-flow"
