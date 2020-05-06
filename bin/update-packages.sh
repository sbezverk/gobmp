#!/usr/bin/bash

current=`pwd`

for d in $(find ${current} -name go.mod | awk '{print $1}'); do
   d=${d%%"/go.mod"}
   echo "+++ Checking folder: ${d}"
   cd ${d}
   go get -u
done
cd ${current}
