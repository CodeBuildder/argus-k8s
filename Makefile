.PHONY: help cluster-up cluster-down cluster-status deploy-cilium deploy-falco \
        deploy-kyverno deploy-observability deploy-agent deploy-ui \
        hubble-ui grafana-ui k9s clean

help:
	@echo "Argus — available commands:"
	@echo ""
	@echo "  Cluster"
	@echo "    make cluster-up            Provision VMs, install k3s, Cilium, namespaces"
	@echo "    make cluster-down          Stop all OrbStack VMs"
	@echo "    make cluster-status        Show node and pod status"
	@echo ""
	@echo "  Security"
	@echo "    make deploy-falco          Install Falco via Helm"
	@echo "    make deploy-kyverno        Install Kyverno + apply policies"
	@echo ""
	@echo "  Observability"
	@echo "    make deploy-observability  Install Prometheus + Grafana + Loki"
	@echo ""
	@echo "  Application"
	@echo "    make deploy-agent          Build and deploy AI agent"
	@echo "    make deploy-ui             Build and deploy React UI"
	@echo ""
	@echo "  Utilities"
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

hubble-ui:
	cilium hubble ui

grafana-ui:
	kubectl port-forward -n monitoring svc/grafana 3000:80

k9s:
	k9s

clean:
	orb delete k3s-master k3s-worker1 k3s-worker2 || true
	rm -f ~/.kube/config
