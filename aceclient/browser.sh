#!/bin/bash

fn=/tmp/daily/index.html

while true
do
  rn=`ps -ef|grep opera |grep -v "grep"|wc -l`
  echo $rn
  if [ ! -s "$fn" ]; then
    if (($rn > 0));then
      ps aux | grep "opera" | cut -c 9-15 | xargs kill -9
    fi
    echo "html not exist!"
    sleep 5
    continue
  fi

  if (($rn < 1));then
    opera -fullscreen &
  fi
  
  sleep 5
done
