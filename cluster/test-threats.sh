#!/bin/bash
# Trigger various security events for Argus testing

echo "🔥 Triggering diverse security events..."

# 1. Shell spawn in container
echo "1. Shell spawn..."
kubectl run test-shell-spawn --image=alpine --restart=Never -- sh -c "sleep 5" 2>/dev/null
sleep 2
kubectl delete pod test-shell-spawn --ignore-not-found 2>/dev/null

# 2. Sensitive file read
echo "2. Sensitive file read..."
kubectl run test-file-read --image=alpine --restart=Never -- sh -c "cat /etc/shadow 2>/dev/null || true; sleep 2" 2>/dev/null
sleep 2
kubectl delete pod test-file-read --ignore-not-found 2>/dev/null

# 3. Privileged container (should be blocked by Kyverno)
echo "3. Privileged container attempt..."
kubectl run test-privileged --image=alpine --restart=Never --privileged -- sleep 5 2>/dev/null
sleep 2
kubectl delete pod test-privileged --ignore-not-found 2>/dev/null

# 4. Disallowed registry (should be blocked by Kyverno)
echo "4. Disallowed registry..."
kubectl run test-bad-registry --image=badregistry.io/malicious:latest --restart=Never 2>/dev/null
sleep 2
kubectl delete pod test-bad-registry --ignore-not-found 2>/dev/null

# 5. Network connection attempt
echo "5. Network connection..."
kubectl run test-network --image=alpine --restart=Never -- sh -c "wget -O- http://example.com 2>/dev/null || true; sleep 2" 2>/dev/null
sleep 2
kubectl delete pod test-network --ignore-not-found 2>/dev/null

# 6. Write to binary directory
echo "6. Binary directory write..."
kubectl run test-bin-write --image=alpine --restart=Never -- sh -c "touch /usr/bin/malicious 2>/dev/null || true; sleep 2" 2>/dev/null
sleep 2
kubectl delete pod test-bin-write --ignore-not-found 2>/dev/null

# 7. Crypto miner simulation
echo "7. Crypto miner process..."
kubectl run test-crypto --image=alpine --restart=Never -- sh -c "echo 'xmrig' > /tmp/miner; sleep 2" 2>/dev/null
sleep 2
kubectl delete pod test-crypto --ignore-not-found 2>/dev/null

echo "Test threats triggered. Check Argus UI for detections!"
