#!/bin/bash

cd /home/marcel/sgx_lab/examples/DistributionVC

echo "=== Cleanup old processes ==="
pkill -9 -f "relay_server" 2>/dev/null
pkill -9 -f "bin/server" 2>/dev/null
sleep 1

echo "=== Starting Relay Servers ==="
./bin/relay_server 1 &
sleep 0.5
./bin/relay_server 2 &
sleep 1

echo "=== Starting Main Server ==="
./bin/server &
sleep 3

echo "=== Testing Receiver ==="
./bin/receiver_client "Hello from receiver"

echo ""
echo "=== Cleanup ==="
pkill -9 -f "relay_server"
pkill -9 -f "bin/server"
