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

        msg=$(docker logs ${cid} 2>&1 | grep "Kafka publisher has been successfully initialized")
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

done=false
found=false
i=0

while [ ${done} == false ]; do

        msg=$(docker logs ${cid} 2>&1 | grep "client 10.1.1.3")
        if [[ ${msg} != "" ]]; then
                done=true
                found=true
        else
                i=$((i+1))
                if [[ ${i} -eq 24 ]]; then
                        done=true
                else
                        sleep 10;
                fi
        fi
done

if [[ ${found} == true ]]; then
        echo "bmp session with 10.1.1.3 came up"
else
    echo "container ${cn} failed to establish bmp session with 10.1.1.3, check gobmp and xr-1 containers' logs..."
	docker logs ${cid}
	docker logs $(docker ps | grep xr-1 | awk '{ print $1 }') 
        exit 1
fi 

exit 0 