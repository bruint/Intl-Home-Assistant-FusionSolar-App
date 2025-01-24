# Home Assistant FusionSolar App Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Default-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub release](https://img.shields.io/github/release/hcraveiro/Home-Assistant-FusionSolar-App.svg)](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App/releases/)

Integrate FusionSolar App into your Home Assistant. This Integration was built due to the fact that some FusionSolar users don't have access to the Kiosk mode or the Northbound API / OpenAPI. If you happen to have access to any of those, please use [Tijs Verkoyen's Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar) 

- [Home Assistant FusionSolar App Integration](#home-assistant-fusionsolar-app-integration)
    - [Installation](#installation)
    - [Configuration](#configuration)
    - [Card configuration](#card-configuration)
    - [Credits](#credits)

## Installation

This integration can be added as a custom repository in HACS and from there you can install it.

When the integration is installed in HACS, you need to add it in Home Assistant: Settings → Devices & Services → Add Integration → Search for FusionSolar App Integration.

The configuration happens in the configuration flow when you add the integration.

## Configuration

To access FusionSolar App you'll need an App account first. When you get it from your installer you'll have an Username and Password. That account is used on this integration. You will need also to provide the Fusion Solar Host you use to login on Fusion Solar App, as you will only be ablet o login on your specific region.

The default sensor's update frequency is 60 seconds, although the FusionSolar App only gets data every 5 minutes. It is just to make sure that as soon as the data can be retrieved from the API the sensors will be updated as soon as possible. After configuring the Integration you can go on the Config Entry and press configure where you'll have the opportunity to change de default update frequency (in seconds). Bare in mind that too frequent will not get data more frequent than 5 minutes and may push the API too much.


### Device Data

After setting up the Integration you will get a Device which will have the following sensors:
* Panels Production (kW)
* Panels Production Today (kWh)
* Panels Production Week (kWh)
* Panels Production Month (kWh)
* Panels Production Year (kWh)
* Panels Production Lifetime (kWh)
* Panels Production Consumption Today (kWh)
* Panels Production Consumption Week (kWh)
* Panels Production Consumption Month (kWh)
* Panels Production Consumption Year (kWh)
* Panels Production Consumption Lifetime (kWh)
* House Load (kW)
* House Load Today (kWh)
* House Load Week (kWh)
* House Load Month (kWh)
* House Load Year (kWh)
* House Load Lifetime (kWh)
* Battery Consumption (kW)
* Battery Consumption Today (kWh)
* Battery Consumption Week (kWh)
* Battery Consumption Month (kWh)
* Battery Consumption Year (kWh)
* Battery Consumption Lifetime (kWh)
* Battery Injection (kW)
* Battery Injection Today (kWh)
* Battery Injection Week (kWh)
* Battery Injection Month (kWh)
* Battery Injection Year (kWh)
* Battery Injection Lifetime (kWh)
* Grid Consumption (kW)
* Grid Consumption Today (kWh)
* Grid Consumption Week (kWh)
* Grid Consumption Month (kWh)
* Grid Consumption Year (kWh)
* Grid Consumption Lifetime (kWh)
* Grid Injection (kW)
* Grid Injection Today (kWh)
* Grid Injection Week (kWh)
* Grid Injection Month (kWh)
* Grid Injection Year (kWh)
* Grid Injection Lifetime (kWh)
* Battery Percentage (%)
* Battery Capacity
* Last Authentication Time

## Card configuration

I have configured a card using [power-flow-card-plus](https://github.com/flixlix/power-flow-card-plus) that looks something like this:
<a href="#"><img src="https://raw.githubusercontent.com/hcraveiro/Home-Assistant-FusionSolar-App/main/assets/card.png"></a>

You can see my configuration here:

```yaml
type: custom:power-flow-card-plus
entities:
  battery:
    state_of_charge: sensor.battery_percentage
    entity:
      consumption: sensor.battery_consumption_power
      production: sensor.battery_injection_power
  grid:
    entity:
      consumption: sensor.grid_consumption_power
      production: sensor.grid_injection_power
    secondary_info: {}
  solar:
    secondary_info: {}
    entity: sensor.panel_production_power
  home:
    secondary_info: {}
    entity: sensor.house_load_power
clickable_entities: true
display_zero_lines: true
use_new_flow_rate_model: true
w_decimals: 0
kw_decimals: 1
min_flow_rate: 0.75
max_flow_rate: 6
max_expected_power: 2000
min_expected_power: 0.01
watt_threshold: 1000
transparency_zero_lines: 0
```

You can find the fusionsolar.png in assets folder. You need to put it in 'www' folder (inside /config).

## Credits

A big thank you to Mark Parker ([msp1974](https://github.com/msp1974)) for providing the Community with a set of [Home Assistant Integration Templates](https://github.com/msp1974/HAIntegrationExamples) from which I started to create this Integration-
Another big thank you to Tijs Verkoyen for his [Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar) as I also took inspiration from there.
