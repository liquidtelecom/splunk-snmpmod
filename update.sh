#!/bin/bash

./build.sh 

splunk install app target/snmpmod.spl -update 1 -auth admin:changeme
