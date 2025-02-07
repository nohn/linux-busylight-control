# Network Traffic Monitor for Busylight control

Monitor network traffic to certain IP ranges and trigger URLs if bandwidth goes above / falls below a threshold.

Preconfigured to monitor MS Teams and Google Meet IP ranges.

## Prerequisites

* Python > 3.12 (very likely to work with lower version, but I haven't tested that)
* ```pip install scapy requests ipaddress argparse logging psutil```

## Usage

### Configuring linux-busylight-control.py

Defaults to watching for MS Teams, MS Convene and Google Meet traffic. You may specify other ip ranges using the allowlist parameter like this:

    --allowlist "192.168.100.0/24" "10.0.0.0/24"

Likewise you can ignore IP ranges (defaults to no IP ranges ignore):

    --ignorelist "224.0.0.0/24"

I'm using https://pypi.org/project/busylight-for-humans/ to drive my Busylight using https://busylight/api/light/0/on?color=red and https://busylight/api/light/0/on?color=green

That data is imported in Home Assistant using busyserve's REST API

      - platform: rest
        name: Busylight Current Color
        resource_template: >-
           {% if is_state('switch.busylight_plug', 'on') %}
             https://busylight/api/light/0/status
           {% else %}
             https://busylight/unavailable.json
           {% endif %}
        value_template: '{{ value_json.color }}'
        scan_interval: 10

and used to trigger things based on that, for example mute smart speakers if in a call etc.
