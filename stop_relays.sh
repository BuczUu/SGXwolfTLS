#!/bin/bash

# Script to stop all relay servers
# Usage: ./stop_relays.sh

echo "=== Stopping All Relay Servers ==="

# Kill all relay_server processes
pkill -f "relay_server"

if [ $? -eq 0 ]; then
    echo "All relay servers stopped successfully"
else
    echo "No relay servers found or error occurred"
fi

sleep 1
echo "Done"
