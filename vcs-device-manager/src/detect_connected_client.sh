#!/bin/bash
logread -e 'DHCPACK' -f >> "/usr/bin/dhcpclient.log"