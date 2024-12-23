# Home Assistant FusionSolar App Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Default-41BDF5.svg)](https://github.com/hacs/integration)

Integrate FusionSolar App into your Home Assistant. This Integration was built due to the fact that some FusionSolar users don't have access to the Kiosk mode or the Northbound API / OpenAPI. If you happen to have access to any of those, please use [Tijs Verkoyen's Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar) 

- [Home Assistant FusionSolar App Integration](#home-assistant-fusionsolar-app-integration)
    - [Installation](#installation)
    - [Configuration](#configuration)
    - [FAQ](#faq)
    - [Credits](#credits)

## Installation

This integration can be added as a custom repository in HACS and from there you can install it.

When the integration is installed in HACS, you need to add it in Home Assistant: Settings → Devices & Services → Add Integration → Search for FusionSolar App Integration.

The configuration happens in the configuration flow when you add the integration.

## Configuration

To access FusionSolar App you'll need an App account first. When you get it from your installer you'll have an Username and Password. That account is used on this integration.
When you add the Integration it will be required, for configuration, said Username and Password. Please add there the ones you got for the App.
It will also be required your Station which right now I can't get dynamically, but you can get it after you login on the URL, something like NE=123456789. Copy that and use it on your configuration.
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

## FAQ

### What is FusionSolar WebApp url?

It's https://eu5.fusionsolar.huawei.com/ where you'll be prompted to Login

## Credits

A big thank you to Mark Parker ([msp1974](https://github.com/msp1974)) for providing the Community with a set of [Home Assistant Integration Templates](https://github.com/msp1974/HAIntegrationExamples) from which I started to create this Integration-
Another big thank you to Tijs Verkoyen for his [Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar) as I also took inspiration from there.