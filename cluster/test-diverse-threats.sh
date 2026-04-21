ag#!/bin/bash
set -e

echo "🎯 Creating diverse security threats for Argus detection..."
echo "These pods comply with Kyverno policies but trigger Falco runtime rules"
echo ""

# Clean up any existing threat pods first
kubectl delete pods -l 'threat-type' --force --grace-period=0 2>/dev/null || true
sleep 2

# 1. Shell spawn in container (Falco will detect shell execution)
echo "1️⃣ Creating pod that spawns shell..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: threat-shell-spawn
  labels:
    threat-type: shell-spawn
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: shell-spawner
    image: docker.io/library/busybox:latest
    command: ["sh"]
    args: ["-c", "while true; do sh -c 'echo spawning shell'; sleep 5; done"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: false
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
      requests:
        cpu: "50m"
        memory: "64Mi"
EOF

# 2. File access patterns (Falco will detect sensitive file reads)
echo "2️⃣ Creating pod that reads sensitive files..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: threat-file-access
  labels:
    threat-type: file-access
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: file-reader
    image: docker.io/library/busybox:latest
    command: ["sh"]
    args: ["-c", "while true; do cat /etc/passwd /etc/group 2>/dev/null || true; sleep 10; done"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: false
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
      requests:
        cpu: "50m"
        memory: "64Mi"
EOF

# 3. Process execution patterns
echo "3️⃣ Creating pod with suspicious process execution..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: threat-process-exec
  labels:
    threat-type: process-exec
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: process-spawner
    image: docker.io/library/busybox:latest
    command: ["sh"]
    args: ["-c", "while true; do ps aux 2>/dev/null || ps; ls -la /proc 2>/dev/null || true; sleep 20; done"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: false
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
      requests:
        cpu: "50m"
        memory: "64Mi"
EOF

# 4. File modification attempts
echo "4️⃣ Creating pod that attempts file modifications..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: threat-file-modify
  labels:
    threat-type: file-modify
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: file-modifier
    image: docker.io/library/busybox:latest
    command: ["sh"]
    args: ["-c", "while true; do touch /tmp/suspicious-file; echo 'data' > /tmp/suspicious-file; rm /tmp/suspicious-file 2>/dev/null || true; sleep 8; done"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: false
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
      requests:
        cpu: "50m"
        memory: "64Mi"
EOF

# 5. Network activity simulation
echo "5️⃣ Creating pod with network activity..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: threat-network-scan
  labels:
    threat-type: network-scan
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: network-scanner
    image: docker.io/library/busybox:latest
    command: ["sh"]
    args: ["-c", "while true; do wget -T 2 -O /dev/null http://example.com 2>/dev/null || true; sleep 15; done"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: false
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
      requests:
        cpu: "50m"
        memory: "64Mi"
EOF

echo ""
echo "✅ Threat simulation pods created successfully!"
echo "📊 These pods will trigger various Falco rules:"
echo "   - Shell spawning in containers"
echo "   - Sensitive file access"
echo "   - Suspicious process execution"
echo "   - File modification patterns"
echo "   - Network activity"
echo ""
echo "🔍 Check the Argus UI Command Center for detections"
echo "⏱️  Pods will run continuously until deleted"
echo ""
echo "To view pod status:"
echo "  kubectl get pods -l 'threat-type'"
echo ""
echo "To clean up all threat pods:"
echo "  kubectl delete pods -l 'threat-type' --force --grace-period=0"
