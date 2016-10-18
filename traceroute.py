#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Multi-source traceroute with geolocation information.
"""

import datetime
import json
import optparse
import os
import re
import signal
import sys
import requests
from subprocess import Popen, PIPE


class Traceroute(object):
    """
    Multi-source traceroute instance.
    """
    def __init__(self, ip_address, source=None, tmp_dir="/tmp",
                 no_geo=False, timeout=120, debug=False):
        super(Traceroute, self).__init__()
        self.ip_address = ip_address
        self.tmp_dir = tmp_dir
        self.no_geo = no_geo
        self.timeout = timeout
        self.debug = debug
        self.locations = {}

    def traceroute(self):
        """
        Instead of running the actual traceroute command, we will fetch
        standard traceroute results from several publicly available webpages
        that are listed at traceroute.org. For each hop, we will then attach
        geolocation information to it.
        """
        self.print_debug("ip_address={}".format(self.ip_address))

        status_code, traceroute = self.execute_cmd(
            'traceroute {}'.format(self.ip_address)
        )

        # hop_num, hosts
        hops = self.get_hops(traceroute)

        # hop_num, hostname, ip_address, rtt
        hops = self.get_formatted_hops(hops)

        if not self.no_geo:
            # hop_num, hostname, ip_address, rtt, latitude, longitude
            hops = self.get_geocoded_hops(hops)

        return hops

    def get_hops(self, traceroute):
        """
        Returns hops from traceroute output in an array of dicts each
        with hop number and the associated hosts data.
        """
        hops = []
        regex = r'^(?P<hop_num>\d+)(?P<hosts>.*?)$'
        lines = traceroute.split("\n")
        for line in lines:
            line = line.strip()
            hop = {}
            if not line:
                continue
            try:
                hop = re.match(regex, line).groupdict()
            except AttributeError:
                continue
            self.print_debug(hop)
            hops.append(hop)
        return hops

    def get_formatted_hops(self, hops):
        """
        Hosts data from get_hops() is represented in a single string.
        We use this function to better represent the hosts data in a dict.
        """
        formatted_hops = []
        regex = r'(?P<h>[\w.-]+) \((?P<i>[\d.]+)\) (?P<r>\d{1,4}.\d{1,4} ms)'
        for hop in hops:
            hop_num = int(hop['hop_num'].strip())
            hosts = hop['hosts'].replace("  ", " ").strip()
            # Using re.findall(), we split the hosts, then for each host,
            # we store a tuple of hostname, IP address and the first RTT.
            hosts = re.findall(regex, hosts)
            for host in hosts:
                hop_context = {
                    'hop_num': hop_num,
                    'hostname': host[0],
                    'ip_address': host[1],
                    'rtt': host[2],
                }
                self.print_debug(hop_context)
                formatted_hops.append(hop_context)
        return formatted_hops

    def get_geocoded_hops(self, hops):
        """
        Returns hops from get_formatted_hops() with geolocation information
        for each hop.
        """
        geocoded_hops = []
        for hop in hops:
            ip_address = hop['ip_address']
            location = None
            if ip_address in self.locations:
                location = self.locations[ip_address]
            else:
                location = self.get_location(ip_address)
                self.locations[ip_address] = location
            if location:
                region = location['region'] if 'region' in location else ''
                postal = location['postal'] if 'postal' in location else ''
                geocoded_hops.append({
                    'hop_num': hop['hop_num'],
                    'hostname': hop['hostname'],
                    'ip_address': hop['ip_address'],
                    'rtt': hop['rtt'],
                    'geo_info': {
                        'city': location['city'],
                        'country': location['country'],
                        'region': region,
                        'postal': postal,
                        'org': location['org'],
                        'latitude': location['loc'].split(',')[0],
                        'longitude': location['loc'].split(',')[1]
                    }
                })
        return geocoded_hops

    def get_location(self, ip_address):
        """
        Returns geolocation information for the given IP address.
        """
        location = None
        url = "http://ipinfo.io/{}".format(ip_address)
        status_code, json_data = self.urlopen(url)
        if status_code == 200 and json_data:
            if 'loc' in json_data:
                location = json_data
        return location

    def execute_cmd(self, cmd):
        """
        Executes given command using subprocess.Popen().
        """
        stdout = ""
        returncode = -1
        process = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        try:
            signal.signal(signal.SIGALRM, self.signal_handler)
            signal.alarm(self.timeout)
            stdout, stderr = process.communicate()
            returncode = process.returncode
            self.print_debug("cmd={}, returncode={}".format(cmd, returncode))
            if returncode != 0:
                self.print_debug("stderr={}".format(stderr))
            signal.alarm(0)
        except Exception as err:
            self.print_debug(str(err))
        return (returncode, stdout)

    def urlopen(self, url, context=None):
        """
        Fetches webpage.
        """
        request = requests.get(url)
        return (request.status_code, request.json())

    def signal_handler(self, signum, frame):
        """
        Raises exception when signal is caught.
        """
        raise Exception("Caught signal {}".format(signum))

    def print_debug(self, msg):
        """
        Prints debug message to standard output.
        """
        if self.debug:
            print("[DEBUG {}] {}".format(datetime.datetime.now(), msg))


def main():
    cmdparser = optparse.OptionParser("%prog --ip_address=IP_ADDRESS")
    cmdparser.add_option(
        "-i", "--ip_address", type="string", default="8.8.8.8",
        help="IP address of destination host (default: 8.8.8.8)")
    cmdparser.add_option(
        "-t", "--tmp_dir", type="string", default="/tmp",
        help=("Temporary directory to store downloaded traceroute results "
              "(default: /tmp)"))
    cmdparser.add_option(
        "-n", "--no_geo", action="store_true", default=False,
        help="No geolocation data (default: False)")
    cmdparser.add_option(
        "-s", "--timeout", type="int", default=120,
        help="Timeout in seconds for all downloads (default: 120)")
    cmdparser.add_option(
        "-d", "--debug", action="store_true", default=False,
        help="Show debug output (default: False)")
    options, _ = cmdparser.parse_args()
    traceroute = Traceroute(ip_address=options.ip_address,
                            tmp_dir=options.tmp_dir,
                            no_geo=options.no_geo,
                            timeout=options.timeout,
                            debug=options.debug)
    hops = traceroute.traceroute()
    print(json.dumps(hops, indent=4))
    return 0


if __name__ == '__main__':
    sys.exit(main())
