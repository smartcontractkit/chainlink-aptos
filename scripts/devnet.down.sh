#!/usr/bin/env bash

echo "Cleaning up devnet container.."

echo "Checking for existing 'chainlink-aptos.devnet' docker container..."
dpid=`docker ps -a | grep chainlink-aptos.devnet | awk '{print $1}'`;
if [ -z "$dpid" ]
then
    echo "No docker devnet container running.";
else
    docker kill $dpid || true;
    docker rm $dpid || docker rm --force $dpid;
fi

docker network rm --force chainlink-aptos.network

echo "Cleanup finished."
