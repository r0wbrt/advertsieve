#!/bin/bash

PIDFile="./advertsieve.pid"

if [ -e $PIDFile ] 
then
	kill -9 $(<"$PIDFile")
	rm $PIDFile
fi 
