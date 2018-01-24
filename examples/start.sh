#!/bin/bash

(./daemon.sh $1 $2 $3) &> /dev/null &

disown -h $!



 
