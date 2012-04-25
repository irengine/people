#!/bin/bash

fn=/tmp/daily/video.txt

while true
do
  if [ ! -s "$fn" ]; then
    echo "video.txt not exist!"
    sleep 3 
    continue
  fi

  fx=`cat $fn`

  rn=`ps -ef|grep vlc |grep -v "grep"|wc -l`
  if (($rn > 0));then
    ps aux | grep "vlc" | cut -c 9-15 | xargs kill -9
  fi

  cd /home/rmrb-enewspaper/clientx/data/5
  vlc -L --fullscreen ${fx}
done

