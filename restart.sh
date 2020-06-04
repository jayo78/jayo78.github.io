#!/bin/bash

is_running=$(ps | grep bundle)
if [ ! -z "$is_running" ]
then
    pid=$(echo ${is_running} | cut -d " " -f 1)
    kill $pid
fi

nohup bundle exec jekyll serve > /dev/null 2>&1 &
