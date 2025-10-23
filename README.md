# Home Assistant FusionSolar App - International Support

This is a fork of the original Home Assistant FusionSolar App integration with added support for **SG5 and International FusionSolar regions**.

## 🚀 New Features

### ✅ Dual Authentication System Support
- **EU5 (New System)**: Uses `dp-session` cookie with `/rest/dpcloud/` endpoints
- **SG5/INTL (Old System)**: Uses `bspsession` cookie with `/rest/neteco/` endpoints
- **Automatic Detection**: The integration automatically detects which system to use

### ✅ Enhanced Session Management
- **Cookie Persistence**: Uses `requests.Session()` for proper cookie handling
- **Dual CSRF Tokens**: Supports both `roarand` and `x-uni-crsf-token` for different endpoints
- **Keep-Alive Mechanisms**: Implements profile and events polling to maintain sessions
- **Dynamic User ID**: Automatically extracts user ID from custom settings endpoint

### ✅ Comprehensive API Support
- **Station List**: Full station data retrieval
- **Real-Time Power**: Current power and energy data
- **Energy Flow**: Detailed power flow between components
- **Energy Balance**: Historical data (daily/monthly/yearly/lifetime)
- **Company Information**: Organization and company data

## 🌍 Supported Regions

| Region | Host | Status | Auth System |
|--------|------|--------|-------------|
| EU5 | `eu5.fusionsolar.huawei.com` | ✅ Supported | New (`dp-session`) |
| SG5 | `sg5.fusionsolar.huawei.com` | ✅ Supported | Old (`bspsession`) |
| INTL | `intl.fusionsolar.huawei.com` | ✅ Supported | Old (`bspsession`) |

## 📦 Installation

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

## ⚙️ Configuration

1. Go to **Configuration** > **Integrations**
2. Click **Add Integration** and search for "FusionSolar App"
3. Enter your credentials:
   - **Username**: Your FusionSolar username
   - **Password**: Your FusionSolar password
   - **Login Host**: Choose your region:
     - `eu5.fusionsolar.huawei.com` (Europe)
     - `sg5.fusionsolar.huawei.com` (Singapore)
     - `intl.fusionsolar.huawei.com` (International)
4. Complete the setup

## 🔧 Technical Details

### Authentication Flow
1. **Login**: Authenticates with FusionSolar using RSA-OAEP encryption
2. **Redirect Handling**: Follows redirects with proper cookie preservation
3. **System Detection**: Automatically detects authentication system
4. **Session Management**: Maintains session with dual keep-alive mechanisms

### API Endpoints
- **Station List**: `/rest/pvms/web/station/v1/station/station-list`
- **Energy Flow**: `/rest/pvms/web/station/v1/overview/energy-flow`
- **Energy Balance**: `/rest/pvms/web/station/v1/overview/energy-balance`
- **Real-Time KPI**: `/rest/pvms/web/station/v1/station/total-real-kpi`
- **Company Info**: `/rest/neteco/web/organization/v2/company/current`

### Keep-Alive Mechanisms
- **Profile Keep-Alive**: `/febs/21.40.38/users/{userId}/profile`
- **Events Keep-Alive**: `/rest/sysfenw/v1/events`

## 🐛 Troubleshooting

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

## 📊 Sensors

The integration provides comprehensive energy monitoring sensors:

### Power Sensors (kW)
- Panel Production Power
- House Load Power
- Battery Consumption/Injection Power
- Grid Consumption/Injection Power

### Energy Sensors (kWh)
- Daily, Weekly, Monthly, Yearly, Lifetime energy data
- Panel production and consumption
- Battery charge/discharge
- Grid import/export

### Status Sensors
- Battery Percentage
- Battery Capacity
- Last Authentication Time

## 🤝 Contributing

This fork adds international support to the original integration. Contributions are welcome!

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Original integration by [hcraveiro](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App)
- Enhanced with SG5/INTL support by [bruint](https://github.com/bruint)