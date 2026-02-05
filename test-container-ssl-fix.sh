#!/bin/bash

# Test script to verify the container SSL discovery fix
# This script creates multiple containers and tests if the collector
# can reliably capture SSL/TLS traffic from all of them

set -e

echo "=== Testing Container SSL Discovery Fix ==="
echo ""

# Cleanup function
cleanup() {
    echo "Cleaning up test containers..."
    docker rm -f test-fix-1 test-fix-2 test-fix-3 test-fix-4 test-fix-5 2>/dev/null || true
}

# Register cleanup on exit
trap cleanup EXIT

# Clean up any existing test containers
cleanup

echo "Step 1: Starting 5 test containers..."
for i in {1..5}; do
    docker run -d --name test-fix-$i node:18 sh -c "
        cat > test.js << 'EOF'
const https = require('https');
setInterval(() => {
    const req = https.get('https://httpbin.org/get?source=test-fix-$i&ts=' + Date.now(), (res) => {
        console.log('test-fix-$i: Status:', res.statusCode);
    });
    req.on('error', (e) => {
        console.error('test-fix-$i: Error:', e.message);
    });
}, 5000);
EOF
        node test.js
    " > /dev/null
    echo "  ✓ Started test-fix-$i"
done

echo ""
echo "Step 2: Waiting 70 seconds to allow:"
echo "  - Collector to scan containers (5s interval)"
echo "  - Processes to load SSL libraries"
echo "  - Skip cache to expire if needed (60s expiration)"
echo "  - Multiple HTTPS requests to be sent"

for i in {70..1}; do
    printf "\r  ⏱  Waiting... %2d seconds remaining" $i
    sleep 1
done
echo ""
echo ""

echo "Step 3: Checking container PIDs..."
for i in {1..5}; do
    pid=$(docker inspect -f '{{.State.Pid}}' test-fix-$i 2>/dev/null || echo "N/A")
    echo "  test-fix-$i: PID $pid"
done

echo ""
echo "Step 4: Checking collector logs for SSL library discoveries..."
echo "  (Looking for 'found SSL library' messages)"
echo ""

# Get collector logs from the last 2 minutes
collector_logs=$(docker logs watchu-collector 2>&1 | grep -A 2 -B 2 "found SSL library" | tail -30 || echo "No SSL discoveries logged")

if echo "$collector_logs" | grep -q "found SSL library"; then
    echo "✓ Collector discovered SSL libraries:"
    echo "$collector_logs" | grep "found SSL library"
else
    echo "⚠ No 'found SSL library' logs found in recent output"
fi

echo ""
echo "Step 5: Checking for captured HTTPS traffic..."
echo "  (Looking for test-fix-* identifiers in collector logs)"
echo ""

captured_count=0
for i in {1..5}; do
    if docker logs watchu-collector 2>&1 | grep -q "test-fix-$i"; then
        echo "  ✓ test-fix-$i: Traffic captured"
        captured_count=$((captured_count + 1))
    else
        echo "  ✗ test-fix-$i: No traffic captured"
    fi
done

echo ""
echo "=== Test Results ==="
echo "Containers tested: 5"
echo "Traffic captured: $captured_count/5"

if [ $captured_count -eq 5 ]; then
    echo ""
    echo "✅ SUCCESS: All containers' SSL traffic was captured!"
    echo "The fix is working correctly."
    exit 0
elif [ $captured_count -gt 0 ]; then
    echo ""
    echo "⚠️  PARTIAL SUCCESS: $captured_count/5 containers captured"
    echo "This is better than before, but some containers still missed."
    exit 1
else
    echo ""
    echo "❌ FAILURE: No containers' SSL traffic was captured"
    echo "The fix may not be working as expected."
    exit 2
fi
