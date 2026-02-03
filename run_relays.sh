#!/bin/bash

# Script to start all 10 relay servers
# Usage: ./run_relays.sh

echo "=== Starting 10 Relay Servers ==="
echo "Each relay will run on port 13001-13010"
echo ""

# Array to store PIDs
declare -a PIDS

# Start 10 relay servers
for i in {1..10}; do
    echo "[$(date '+%H:%M:%S')] Starting Relay Server $i (port $((13000 + $i)))..."
    ./bin/relay_server $i &
    PIDS+=($!)
    sleep 0.5  # Small delay between launches
done

echo ""
echo "=== All 10 Relay Servers Started ==="
echo "PIDs: ${PIDS[@]}"
echo ""
echo "To stop all relay servers, press Ctrl+C or run:"
echo "  kill ${PIDS[@]}"
echo ""

# Wait for all background processes
wait
