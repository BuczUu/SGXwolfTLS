#!/bin/bash

cd /home/marcel/sgx_lab/examples/DistributionVC

echo "=== Building ==="
make clean > /tmp/build.log 2>&1
make >> /tmp/build.log 2>&1

if [ $? -ne 0 ]; then
    echo "Build failed, checking log:"
    tail -50 /tmp/build.log
    exit 1
fi

echo "Build successful!"
echo ""
echo "=== Starting Relay Servers ==="
./bin/relay_server 1 > /tmp/relay1.log 2>&1 &
RELAY1_PID=$!
echo "Relay 1 started (PID: $RELAY1_PID)"

./bin/relay_server 2 > /tmp/relay2.log 2>&1 &
RELAY2_PID=$!
echo "Relay 2 started (PID: $RELAY2_PID)"

sleep 1

echo ""
echo "=== Starting Server ==="
./bin/server > /tmp/server.log 2>&1 &
SERVER_PID=$!
echo "Server started (PID: $SERVER_PID)"

sleep 2

echo ""
echo "=== Testing Receiver ==="
./bin/receiver_client "Hello from receiver" > /tmp/receiver.log 2>&1
RECEIVER_RET=$?

echo ""
echo "=== Results ==="
if [ $RECEIVER_RET -eq 0 ]; then
    echo "✓ Receiver test PASSED"
    cat /tmp/receiver.log
else
    echo "✗ Receiver test FAILED"
    echo "Server output:"
    cat /tmp/server.log
    echo ""
    echo "Relay 1 output:"
    cat /tmp/relay1.log
    echo ""
    echo "Relay 2 output:"
    cat /tmp/relay2.log
    echo ""
    echo "Receiver output:"
    cat /tmp/receiver.log
fi

echo ""
echo "Cleaning up..."
kill $RELAY1_PID $RELAY2_PID $SERVER_PID 2>/dev/null
wait 2>/dev/null

exit $RECEIVER_RET
