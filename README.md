# traceroute
Traceroute is a Python script that allows you to get traceroute results with associated geolocation information for each hop for a specified host from geographically distant source(s). Demo: [IP Address Lookup](https://dazzlepod.com/ip/) (under "Visual Traceroute" tab)

## Installation

Save traceroute.py into a directory with its path stored in your PYTHONPATH environment variable.

## Usage

Try the following from your Python interpreter:

    >>> from traceroute import Traceroute
    >>> traceroute = Traceroute(ip_address='8.8.8.8')
    >>> hops = traceroute.traceroute()
    >>> hops
    [{'hostname': 'gigagate1', 'longitude': -74.6597, 'rtt': '0.700 ms', 'hop_num': 1, 'latitude': 40.3756, 'ip_address': '128.112.128.114'}, {'hostname': 'vgate1', 'longitude': -74.6597, 'rtt': '0.375 ms', 'hop_num': 2, 'latitude': 40.3756, 'ip_address': '128.112.12.22'}, {'hostname': 'te-1-4-3998-pe01.philadelphia.pa.ibone.comcast.net', 'longitude': -75.3697, 'rtt': '18.296 ms', 'hop_num': 3, 'latitude': 40.3265, 'ip_address': '24.104.128.89'}, {'hostname': 'te-0-1-0-12-cr01.ashburn.va.ibone.comcast.net', 'longitude': -97.0, 'rtt': '28.446 ms', 'hop_num': 4, 'latitude': 38.0, 'ip_address': '68.86.84.177'}, {'hostname': 'pos-0-2-0-0-pe01.ashburn.va.ibone.comcast.net', 'longitude': -97.0, 'rtt': '21.968 ms', 'hop_num': 5, 'latitude': 38.0, 'ip_address': '68.86.86.70'}, {'hostname': '75.149.231.62', 'longitude': -97.0, 'rtt': '20.685 ms', 'hop_num': 6, 'latitude': 38.0, 'ip_address': '75.149.231.62'}, {'hostname': '209.85.252.80', 'longitude': -122.0574, 'rtt': '18.383 ms', 'hop_num': 7, 'latitude': 37.4192, 'ip_address': '209.85.252.80'}, {'hostname': '209.85.252.46', 'longitude': -122.0574, 'rtt': '18.541 ms', 'hop_num': 7, 'latitude': 37.4192, 'ip_address': '209.85.252.46'}, {'hostname': '209.85.252.80', 'longitude': -122.0574, 'rtt': '19.723 ms', 'hop_num': 7, 'latitude': 37.4192, 'ip_address': '209.85.252.80'}, {'hostname': '72.14.238.82', 'longitude': -122.0574, 'rtt': '15.124 ms', 'hop_num': 9, 'latitude': 37.4192, 'ip_address': '72.14.238.82'}, {'hostname': '72.14.238.16', 'longitude': -122.0574, 'rtt': '15.564 ms', 'hop_num': 9, 'latitude': 37.4192, 'ip_address': '72.14.238.16'}, {'hostname': '216.239.49.149', 'longitude': -122.0574, 'rtt': '23.253 ms', 'hop_num': 10, 'latitude': 37.4192, 'ip_address': '216.239.49.149'}, {'hostname': 'google-public-dns-a.google.com', 'longitude': -122.0574, 'rtt': '13.020 ms', 'hop_num': 11, 'latitude': 37.4192, 'ip_address': '8.8.8.8'}]
    >>>

You can also run the script directly by passing in the --ip_address option:

    $ python traceroute.py --ip_address=8.8.8.8
    [
        {
            "hostname": "gigagate1",
            "longitude": -74.659700000000001,
            "rtt": "0.922 ms",
            "hop_num": 1,
            "latitude": 40.375599999999999,
            "ip_address": "128.112.128.114"
        },
        {
            "hostname": "vgate1",
            "longitude": -74.659700000000001,
            "rtt": "0.381 ms",
            "hop_num": 2,
            "latitude": 40.375599999999999,
            "ip_address": "128.112.12.22"
        },
        {
            "hostname": "te-1-4-3998-pe01.philadelphia.pa.ibone.comcast.net",
            "longitude": -75.369699999999995,
            "rtt": "11.116 ms",
            "hop_num": 3,
            "latitude": 40.326500000000003,
            "ip_address": "24.104.128.89"
        },
        {
            "hostname": "te-0-1-0-12-cr01.ashburn.va.ibone.comcast.net",
            "longitude": -97.0,
            "rtt": "25.472 ms",
            "hop_num": 4,
            "latitude": 38.0,
            "ip_address": "68.86.84.177"
        },
        {
            "hostname": "pos-0-2-0-0-pe01.ashburn.va.ibone.comcast.net",
            "longitude": -97.0,
            "rtt": "18.210 ms",
            "hop_num": 5,
            "latitude": 38.0,
            "ip_address": "68.86.86.70"
        },
        {
            "hostname": "75.149.231.62",
            "longitude": -97.0,
            "rtt": "11.732 ms",
            "hop_num": 6,
            "latitude": 38.0,
            "ip_address": "75.149.231.62"
        },
        {
            "hostname": "209.85.252.80",
            "longitude": -122.0574,
            "rtt": "21.879 ms",
            "hop_num": 7,
            "latitude": 37.419199999999996,
            "ip_address": "209.85.252.80"
        },
        {
            "hostname": "72.14.238.70",
            "longitude": -122.057403564453,
            "rtt": "13.193 ms",
            "hop_num": 9,
            "latitude": 37.419200897216797,
            "ip_address": "72.14.238.70"
        },
        {
            "hostname": "72.14.238.16",
            "longitude": -122.0574,
            "rtt": "11.585 ms",
            "hop_num": 9,
            "latitude": 37.419199999999996,
            "ip_address": "72.14.238.16"
        },
        {
            "hostname": "72.14.238.82",
            "longitude": -122.0574,
            "rtt": "11.560 ms",
            "hop_num": 9,
            "latitude": 37.419199999999996,
            "ip_address": "72.14.238.82"
        },
        {
            "hostname": "216.239.49.145",
            "longitude": -122.0574,
            "rtt": "21.959 ms",
            "hop_num": 10,
            "latitude": 37.419199999999996,
            "ip_address": "216.239.49.145"
        },
        {
            "hostname": "72.14.232.25",
            "longitude": -122.0574,
            "rtt": "12.817 ms",
            "hop_num": 10,
            "latitude": 37.419199999999996,
            "ip_address": "72.14.232.25"
        },
        {
            "hostname": "216.239.49.145",
            "longitude": -122.0574,
            "rtt": "15.652 ms",
            "hop_num": 10,
            "latitude": 37.419199999999996,
            "ip_address": "216.239.49.145"
        },
        {
            "hostname": "google-public-dns-a.google.com",
            "longitude": -122.0574,
            "rtt": "12.514 ms",
            "hop_num": 11,
            "latitude": 37.419199999999996,
            "ip_address": "8.8.8.8"
        }
    ]