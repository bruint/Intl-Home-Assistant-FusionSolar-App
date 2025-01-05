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
* House Load (kW)
* Battery Consumption (kW)
* Battery Injections (kW)
* Grid Consumption (kW)
* Grid Injection (kW)
* Battery Percentage (%)
* Last Authentication Time

## Card configuration

I have configured a card using picture-elements that looks something like this:
<a href="#"><img src="https://raw.githubusercontent.com/hcraveiro/Home-Assistant-FusionSolar-App/main/assets/card.png"></a>

You can see my configuration here:

```yaml
type: picture-elements
elements:
  - type: state-label
    entity: sensor.house_load_power
    style:
      top: 80%
      left: 50%
      color: black
  - type: state-label
    entity: sensor.panel_production_power
    style:
      top: 30%
      left: 50%
      color: black
  - type: conditional
    conditions:
      - entity: sensor.panel_production_power
        state_not: "0.0"
    elements:
      - type: icon
        entity: sensor.panel_production_power
        icon: mdi:arrow-down
        style:
          top: 48%
          left: 51%
          color: orange
          width: 31px
          height: 30px
  - type: conditional
    conditions:
      - entity: sensor.battery_consumption_power
        state_not: "0.0"
      - entity: sensor.battery_injection_power
        state: "0.0"
    elements:
      - type: state-label
        entity: sensor.battery_consumption_power
        style:
          top: 54%
          left: 18%
          color: black
      - type: icon
        entity: sensor.battery_consumption_power
        icon: mdi:arrow-right
        style:
          top: 53%
          left: 40%
          color: cadetblue
          width: 30px
          height: 32px
  - type: conditional
    conditions:
      - entity: sensor.battery_injection_power
        state_not: "0.0"
      - entity: sensor.battery_consumption_power
        state: "0.0"
    elements:
      - type: state-label
        entity: sensor.battery_injection_power
        style:
          top: 54%
          left: 18%
          color: black
      - type: icon
        entity: sensor.battery_consumption_power
        icon: mdi:arrow-left
        style:
          top: 49%
          left: 40%
          color: cadetblue
          width: 30px
          height: 30px
  - type: conditional
    conditions:
      - entity: sensor.battery_consumption_power
        state: "0.0"
      - entity: sensor.battery_injection_power
        state: "0.0"
    elements:
      - type: state-label
        entity: sensor.battery_consumption_power
        style:
          top: 54%
          left: 18%
          color: black
  - type: conditional
    conditions:
      - entity: sensor.grid_consumption_power
        state_not: "0.0"
      - entity: sensor.grid_injection_power
        state: "0.0"
    elements:
      - type: state-label
        entity: sensor.grid_consumption_power
        style:
          top: 55%
          left: 83%
          color: black
      - type: icon
        entity: sensor.grid_consumption_power
        icon: mdi:arrow-left
        style:
          top: 52%
          left: 60%
          color: cadetblue
          width: 30px
          height: 26px
  - type: conditional
    conditions:
      - entity: sensor.grid_injection_power
        state_not: "0.0"
      - entity: sensor.grid_consumption_power
        state: "0.0"
    elements:
      - type: state-label
        entity: sensor.grid_injection_power
        style:
          top: 55%
          left: 83%
          color: black
      - type: icon
        entity: sensor.grid_injection_power
        icon: mdi:arrow-right
        style:
          top: 49%
          left: 60%
          color: cadetblue
          width: 30px
          height: 28px
  - type: conditional
    conditions:
      - entity: sensor.grid_consumption_power
        state: "0.0"
      - entity: sensor.grid_injection_power
        state: "0.0"
    elements:
      - type: state-label
        entity: sensor.grid_consumption_power
        style:
          top: 55%
          left: 83%
          color: black
  - type: state-label
    entity: sensor.battery_percentage
    style:
      top: 45%
      left: 15%
      color: black
      width: 21px
      height: 33px
  - type: state-label
    entity: sensor.house_load_last_updated_label
    style:
      top: 97%
      left: 21%
      color: grey
image: /local/fusionsolar.png
```

You can find the fusionsolar.png in assets folder. You need to put it in 'www' folder (inside /config).

## Credits

A big thank you to Mark Parker ([msp1974](https://github.com/msp1974)) for providing the Community with a set of [Home Assistant Integration Templates](https://github.com/msp1974/HAIntegrationExamples) from which I started to create this Integration-
Another big thank you to Tijs Verkoyen for his [Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar) as I also took inspiration from there.
