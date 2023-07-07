#!/usr/bin/bash

cn=$1
cid=$(docker ps | grep ${cn} | awk '{ print $1 }')

if [[ ${cid} == "" ]]; then
        echo "no container ${cn} detected"
        exit 1
fi

echo "Container id: ${cid}"

done=false
found=false
i=0

while [ ${done} == false ]; do

        msg=$(docker logs ${cid} | grep "Kafka publisher has been successfully initialized")
        if [[ ${msg} != "" ]]; then
                done=true
                found=true
        else
                i=$((i+1))
                if [[ ${i} -eq 12 ]]; then
                        done=true
                else
                        sleep 10;
                fi
        fi
done

if [[ ${found} == true ]]; then
        echo "successfully connected to kafka"
else
        echo "container ${cn} failed to connect to kafka, check container logs..."
        docker logs ${cid}
        exit 1
fi

exit 0 