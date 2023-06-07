#!/bin/sh

logread -e 'DHCPACK' -f >> "/usr/bin/dhcpclient.log"