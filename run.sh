#!/bin/bash
#
# run.sh - DistributionVC Test Script
# Starts all components in separate terminals
#

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Check if built
if [ ! -f "bin/server" ] || [ ! -f "bin/receiver_client" ] || [ ! -f "bin/relay_server" ]; then
    echo "=== Building DistributionVC ==="
    make clean
    make
fi

echo ""
echo "=== DistributionVC Ready to Run ==="
echo ""
echo "To start the system, open 4 terminals:"
echo ""
echo "Terminal 1 (Main Server):"
echo "  cd $PROJECT_DIR"
echo "  export LD_LIBRARY_PATH=$HOME/sgx_lab/sgxsdk/lib64:\$LD_LIBRARY_PATH"
echo "  ./bin/server"
echo ""
echo "Terminal 2 (Data Relay 1):"
echo "  cd $PROJECT_DIR"
echo "  export LD_LIBRARY_PATH=$HOME/sgx_lab/sgxsdk/lib64:\$LD_LIBRARY_PATH"
echo "  ./bin/relay_server 1"
echo ""
echo "Terminal 3 (Data Relay 2):"
echo "  cd $PROJECT_DIR"
echo "  export LD_LIBRARY_PATH=$HOME/sgx_lab/sgxsdk/lib64:\$LD_LIBRARY_PATH"
echo "  ./bin/relay_server 2"
echo ""
echo "Terminal 4 (Receiver Client):"
echo "  cd $PROJECT_DIR"
echo "  export LD_LIBRARY_PATH=$HOME/sgx_lab/sgxsdk/lib64:\$LD_LIBRARY_PATH"
echo "  ./bin/receiver_client \"Hello from receiver\""
echo ""
echo "Or run all together with:"
echo "  gnome-terminal -- bash -c 'cd $PROJECT_DIR; export LD_LIBRARY_PATH=$HOME/sgx_lab/sgxsdk/lib64:\$LD_LIBRARY_PATH; ./bin/server; bash'"
echo "  gnome-terminal -- bash -c 'cd $PROJECT_DIR; export LD_LIBRARY_PATH=$HOME/sgx_lab/sgxsdk/lib64:\$LD_LIBRARY_PATH; ./bin/relay_server 1; bash'"
echo "  gnome-terminal -- bash -c 'cd $PROJECT_DIR; export LD_LIBRARY_PATH=$HOME/sgx_lab/sgxsdk/lib64:\$LD_LIBRARY_PATH; ./bin/relay_server 2; bash'"
echo "  gnome-terminal -- bash -c 'cd $PROJECT_DIR; export LD_LIBRARY_PATH=$HOME/sgx_lab/sgxsdk/lib64:\$LD_LIBRARY_PATH; sleep 2; ./bin/receiver_client \"Test data\"; bash'"
echo ""
