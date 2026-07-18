.PHONY: help cluster-up cluster-down cluster-status deploy-cilium deploy-falco \
        deploy-kyverno deploy-observability deploy-agent deploy-ui \
        setup-local dev-agent dev-ui demo-local demo-cluster demo-cluster-dry-run hubble-ui grafana-ui k9s \
        test test-agent test-ui test-cluster-demo simulate-threats clean

THREAT_COUNT ?= 10
THREAT_SCENARIO ?= mixed
THREAT_SEED ?=
comma := ,
THREAT_SEED_FIELD = $(if $(THREAT_SEED),$(comma) "seed": $(THREAT_SEED),)

help:
	@echo "Argus — available commands:"
	@echo ""
	@echo "  Cluster"
	@echo "    make cluster-up            Provision VMs, install k3s, Cilium, namespaces"
	@echo "    make cluster-down          Stop all OrbStack VMs"
	@echo "    make cluster-status        Show node and pod status"
	@echo "    make demo-cluster          Run real-cluster threats and console"
	@echo "    make demo-cluster-dry-run  Validate cluster prerequisites without changes"
	@echo ""
	@echo "  Security"
	@echo "    make deploy-falco          Install Falco via Helm"
	@echo "    make deploy-kyverno        Install Kyverno + apply policies"
	@echo ""
	@echo "  Observability"
	@echo "    make deploy-observability  Install Prometheus + Grafana + Loki"
	@echo ""
	@echo "  Application"
	@echo "    make setup-local           Install local backend and UI dependencies"
	@echo "    make demo-local            Start a populated cluster-free demo"
	@echo "    make dev-agent             Start only the backend on localhost:8000"
	@echo "    make dev-ui                Start only the console on localhost:5173"
	@echo "    make deploy-agent          Build and deploy AI agent"
	@echo "    make deploy-ui             Build and deploy React UI"
	@echo ""
	@echo "  Utilities"
	@echo "    make test                  Run agent tests and build the UI"
	@echo "    make test-cluster-demo     Test cluster-demo safety guards"
	@echo "    make simulate-threats      Generate randomized demo incidents"
	@echo "    make hubble-ui             Open Hubble network flow UI"
	@echo "    make grafana-ui            Port-forward Grafana to localhost:3000"
	@echo "    make k9s                   Open k9s cluster terminal UI"
	@echo "    make clean                 Destroy VMs and reset kubeconfig"

cluster-up:
	@echo "==> Provisioning VMs..."
	@bash cluster/bootstrap/01-provision-vms.sh
	@echo "==> Installing k3s master..."
	@bash cluster/bootstrap/02-install-master.sh
	@echo "==> Joining workers..."
	@bash cluster/bootstrap/03-join-workers.sh
	@echo "==> Installing Cilium..."
	@bash cluster/bootstrap/04-install-cilium.sh
	@echo "==> Applying namespaces..."
	@kubectl apply -f cluster/namespaces/namespaces.yaml
	@echo "==> Cluster is ready."

cluster-down:
	orb stop k3s-master k3s-worker1 k3s-worker2

cluster-status:
	@echo "==> Nodes:"
	@kubectl get nodes -o wide
	@echo ""
	@echo "==> Pods (all namespaces):"
	@kubectl get pods -A
	@echo ""
	@echo "==> Cilium status:"
	@cilium status

deploy-falco:
	helm repo add falcosecurity https://falcosecurity.github.io/charts
	helm repo update
	helm upgrade --install falco falcosecurity/falco \
		--namespace kube-system \
		--values security/falco/values.yaml

deploy-kyverno:
	helm repo add kyverno https://kyverno.github.io/kyverno
	helm repo update
	helm upgrade --install kyverno kyverno/kyverno \
		--namespace kyverno \
		--create-namespace
	kubectl apply -f security/kyverno/no-root-containers.yaml
	kubectl apply -f security/kyverno/require-resource-limits.yaml
	kubectl apply -f security/kyverno/approved-registries.yaml

deploy-observability:
	@echo "TODO: implement in Module 3"

deploy-agent:
	@echo "==> Deploying Argus agent..."
	@cd agent && ANTHROPIC_API_KEY='${ANTHROPIC_API_KEY}' bash deploy.sh

deploy-ui:
	@echo "TODO: implement in Module 5"

setup-local:
	python3 -m venv .venv
	.venv/bin/pip install -r agent/requirements.txt
	npm --prefix ui ci

dev-agent:
	@test -x .venv/bin/python || (echo "Missing local environment. Run: make setup-local" && exit 1)
	@cd agent/src && ../../.venv/bin/python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000

dev-ui:
	@test -d ui/node_modules || (echo "Missing UI dependencies. Run: make setup-local" && exit 1)
	@npm --prefix ui run dev -- --host 127.0.0.1

demo-local:
	@bash scripts/demo-local.sh "$(THREAT_COUNT)" "$(THREAT_SCENARIO)" "$(THREAT_SEED)"

demo-cluster:
	@DEMO_CLUSTER_CONTEXT="$(DEMO_CLUSTER_CONTEXT)" \
	 DEMO_NAMESPACE="$(or $(DEMO_NAMESPACE),argus-demo)" \
	 DEMO_WAIT_SECONDS="$(or $(DEMO_WAIT_SECONDS),30)" \
	 DEMO_KEEP_RESOURCES="$(or $(DEMO_KEEP_RESOURCES),false)" \
	 bash scripts/demo-cluster.sh

demo-cluster-dry-run:
	@DEMO_NAMESPACE="$(or $(DEMO_NAMESPACE),argus-demo)" \
	 DEMO_WAIT_SECONDS="$(or $(DEMO_WAIT_SECONDS),30)" \
	 bash scripts/demo-cluster.sh --dry-run

test: test-agent test-ui

test-agent:
	@.venv/bin/python -m pytest -q agent

test-ui:
	@npm --prefix ui run build

test-cluster-demo:
	@bash scripts/tests/test-demo-cluster.sh

simulate-threats:
	@curl --fail --silent http://localhost:8000/health >/dev/null || \
		(echo "Argus backend is not running on localhost:8000."; \
		 echo "Start it with: make dev-agent"; \
		 echo "Or launch the complete cluster-free demo with: make demo-local"; \
		 exit 1)
	@curl --fail --silent --show-error \
		-X POST http://localhost:8000/simulate-threats \
		-H "Content-Type: application/json" \
		-d '{"count": $(THREAT_COUNT), "scenario": "$(THREAT_SCENARIO)"$(THREAT_SEED_FIELD)}'
	@echo

hubble-ui:
	cilium hubble ui

grafana-ui:
	kubectl port-forward -n monitoring svc/grafana 3000:80

k9s:
	k9s

clean:
	orb delete k3s-master k3s-worker1 k3s-worker2 || true
	rm -f ~/.kube/config
