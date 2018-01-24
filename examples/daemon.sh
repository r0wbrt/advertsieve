#!/bin/bash

PIDFile="$1"

if [ -e $PIDFile ] 
then
	kill -9 $(<"$PIDFile")
	rm $PIDFile
fi

if [ -n "$3"	 ]; then
	$1 $2 &>> "$3" &
else
	$1 $2 &>> "/dev/null" &
fi

echo $! > $PIDFile

wait

rm $PIDFile &> "/dev/null"
