#!/bin/bash

fn=/tmp/daily/rcmd.txt

while true
do
  if [ ! -s "$fn" ]; then
    sleep 5 
    continue
  fi

  fx=`cat $fn`
  rm $fn
  
  if [ "$fx" == "1" ]; then

  fi

  if [ "$fx" == "2" ]; then

  fi

  if [ "$fx" == "3" ]; then

  fi

  if [ "$fx" == "4" ]; then

  fi

  if [ "$fx" == "5" ]; then

  fi

  if [ "$fx" == "6" ]; then

  fi
done
