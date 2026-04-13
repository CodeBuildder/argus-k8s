.PHONY: help cluster-up cluster-down deploy-cilium deploy-falco deploy-kyverno \
        deploy-observability deploy-agent deploy-ui status clean

help:
	@echo "Argus — available commands:"
	@echo ""
	@echo "  Cluster"
	@echo "    make cluster-up          Provision OrbStack VMs and bootstrap k3s"
	@echo "    make cluster-down        Stop all OrbStack VMs"
	@echo "    make cluster-status      Show node and pod status"
	@echo ""
	@echo "  Security"
	@echo "    make deploy-cilium       Install Cilium CNI + enable Hubble"
	@echo "    make deploy-falco        Install Falco via Helm"
	@echo "    make deploy-kyverno      Install Kyverno + apply policies"
	@echo ""
	@echo "  Observability"
	@echo "    make deploy-observability  Install Prometheus + Grafana + Loki"
	@echo ""
	@echo "  Application"
	@echo "    make deploy-agent        Build and deploy AI agent"
	@echo "    make deploy-ui           Build and deploy React UI"
	@echo ""
	@echo "  Utilities"
	@echo "    make hubble-ui           Open Hubble network flow UI"
	@echo "    make grafana-ui          Port-forward Grafana to localhost:3000"
	@echo "    make k9s                 Open k9s cluster terminal UI"
	@echo "    make clean               Destroy VMs and reset kubeconfig"

cluster-up:
	@echo "TODO: implement in cluster/bootstrap/"

cluster-down:
	orb stop k3s-master k3s-worker1 k3s-worker2

cluster-status:
	kubectl get nodes -o wide
	kubectl get pods -A

deploy-cilium:
	@echo "TODO: implement after cluster-up is working"

deploy-falco:
	@echo "TODO: implement after Cilium is running"

deploy-kyverno:
	@echo "TODO: implement after Falco is running"

deploy-observability:
	@echo "TODO: implement after security layer is deployed"

deploy-agent:
	@echo "TODO: implement after observability is running"

deploy-ui:
	@echo "TODO: implement after agent is running"

hubble-ui:
	cilium hubble ui

grafana-ui:
	kubectl port-forward -n monitoring svc/grafana 3000:80

k9s:
	k9s

clean:
	orb delete k3s-master k3s-worker1 k3s-worker2 || true
	rm -f ~/.kube/config
