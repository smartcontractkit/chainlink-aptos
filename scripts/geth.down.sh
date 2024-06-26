#!/usr/bin/env bash
# TODO: this script needs to be replaced with a predefined K8s enviroment

echo "Cleaning up geth container.."

echo "Checking for existing 'chainlink.geth' docker container..."
dpid=$(docker ps -a | grep chainlink.geth | awk '{print $1}')
if [ -z "$dpid" ]; then
	echo "No docker geth container running."
else
	docker kill $dpid
	docker rm $dpid
fi

echo "Cleanup finished."
