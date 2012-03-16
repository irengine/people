#!/bin/bash
export DISPLAY=:0.0
ps aux | grep "vlc" | cut -c 9-15 | xargs kill -9
ps aux | grep "opera" | cut -c 9-15 | xargs kill -9
./client
