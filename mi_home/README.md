# Mi Home
Parser for Xiaomi Mi Home app on Android

## Supported Artifacts
Currently only a limited subset of artifacts is supported:
- Home Information
- Last Home Environment Readings
- Event Logs from certain devices:
  - Temperature Sensors
  - Motion Sensors

Other devices may be supported but are untested.

## Known Issues
Xiaomi stores a timezone specific Unix Timestamp for some device logs.
When decoding the files the TZ is not accounted for, and some timestamps might be off by some hours. 
This is generally detectable by an offset of UTC+TZ between the event timestamp and the log timestamp.
It is not however automatically detected by the plugin and fixed.
