# FusionSolar SG5 Investigation - Summary

## Problem
The Home Assistant FusionSolar App integration doesn't work with the sg5 region.

## What We Discovered

### SG5 Uses Different Authentication System
- **EU5 (New)**: Uses `dp-session` cookie, `/rest/dpcloud/` endpoints
- **SG5 (Old)**: Uses `bspsession` cookie, `/rest/neteco/` endpoints

### Working SG5 Endpoints
✅ `/rest/neteco/web/organization/v2/company/current` - Company info  
✅ `/rest/pvms/web/station/v1/station/total-real-kpi` - Power data  
❌ `/rest/pvms/web/station/v1/station/station-list` - 404 Not Found  

### Key Data Retrieved
- Company ID: `NE=33564653`
- Current Power: 0.0 kW
- Daily Energy: 31.11 kWh
- Cumulative Energy: 25998.63 kWh

## Solution Needed

Update `custom_components/fusion_solar_app/api.py`:

1. **Use requests.Session()** to preserve cookies
2. **Detect auth system** based on cookie type (`dp-session` vs `bspsession`)
3. **Use appropriate endpoints** for each system
4. **Handle redirects** with `allow_redirects=True` for sg5

## Test Scripts

- `test_intl_api.py` - Test international endpoint login and API access
- `test_sg5_data.py` - Test sg5-specific data retrieval

## Next Steps

1. Test international endpoint with `python3 test_intl_api.py`
2. Apply code changes to Home Assistant integration
3. Test with sg5.fusionsolar.huawei.com in Home Assistant

## Files Cleaned Up

Removed 10+ redundant markdown and Python files, keeping only essential test scripts.