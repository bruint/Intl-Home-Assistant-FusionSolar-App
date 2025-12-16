# Home Assistant FusionSolar App - SG5/INTL Support

This is a simplified Home Assistant FusionSolar App integration with support for **SG5 and International FusionSolar regions**.

## Features

### Authentication System
- **SG5/INTL Support**: Uses `bspsession` cookie with `/rest/neteco/` endpoints
- **Session Management**: Uses `requests.Session()` for proper cookie handling
- **CSRF Token**: Uses `roarand` header for API requests
- **Keep-Alive**: Implements events polling to maintain sessions

### API Support
- **Station List**: Station data retrieval
- **Real-Time Power**: Current solar generation power in kW

## Supported Regions

| Region | Host | Status | Auth System |
|--------|------|--------|-------------|
| SG5 | `sg5.fusionsolar.huawei.com` | ✅ Supported | `bspsession` |
| INTL | `intl.fusionsolar.huawei.com` | ✅ Supported | `bspsession` |

## Installation

### Option 1: HACS (Recommended)
1. Add this repository to HACS: `https://github.com/bruint/Intl-Home-Assistant-FusionSolar-App`
2. Install "FusionSolar App"
3. Restart Home Assistant
4. Add the integration via Configuration > Integrations

### Option 2: Manual Installation
1. Download the latest release
2. Copy the `fusion_solar_app` folder to your `custom_components` directory
3. Restart Home Assistant
4. Add the integration via Configuration > Integrations

## Configuration

1. Go to **Configuration** > **Integrations**
2. Click **Add Integration** and search for "FusionSolar App"
3. Enter your credentials:
   - **Username**: Your FusionSolar username
   - **Password**: Your FusionSolar password
   - **Login Host**: Choose your region:
     - `sg5.fusionsolar.huawei.com` (Singapore)
     - `intl.fusionsolar.huawei.com` (International)
4. Complete the setup

## Technical Details

### Authentication Flow
1. **Login**: Authenticates with FusionSolar using RSA-OAEP encryption
2. **Redirect Handling**: Follows redirects with proper cookie preservation
3. **Session Management**: Maintains session with keep-alive mechanism

### API Endpoints
- **Station List**: `/rest/pvms/web/station/v1/station/station-list`
- **Energy Flow**: `/rest/pvms/web/station/v1/overview/energy-flow`
- **Keep-Alive**: `/rest/sysfenw/v1/events`

## Troubleshooting

### Common Issues
1. **Login Failed**: Verify your credentials and region host
2. **Session Expired**: The integration automatically handles session renewal
3. **No Data**: Check if your station is properly configured in FusionSolar

### Debug Logging
Enable debug logging in `configuration.yaml`:
```yaml
logger:
  logs:
    custom_components.fusion_solar_app: debug
```

## Sensors

The integration provides a single sensor for solar generation monitoring:

### Power Sensor (kW)
- **Panel Production Power**: Current solar generation power in kilowatts

This simplified sensor provides the foundation for building more extensive Home Assistant energy capabilities in the future.

## Contributing

Contributions are welcome!

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Original integration by [hcraveiro](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App)
- Enhanced with SG5/INTL support by [bruint](https://github.com/bruint)
