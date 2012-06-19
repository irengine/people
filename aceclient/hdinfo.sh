#!/bin/bash

mkdir /tmp/daily
/home/rmrb-enewspaper/.clientx/bin/hdinfo /dev/sda1 /tmp/daily/id.ini
chown -R rmrb-enewspaper.rmrb-enewspaper /tmp/daily
