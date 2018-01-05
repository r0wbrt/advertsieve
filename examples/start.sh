#!/bin/bash

nohup ./daemon.sh $1 &
disown $!



 
