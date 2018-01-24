#!/bin/bash

PIDFile=$1

if [ -e $PIDFile ] 
then
	kill -9 $(<"$PIDFile")
	rm $PIDFile 2> "/dev/null"
fi 
