.PHONY: lab clean test build baseline collect destroy

build:
	docker build -t soc-gateway:latest configs/gateway/
	docker build -t soc-host:latest services/host/

lab: build
	python3 scripts/build_configs.py
	containerlab deploy --topo topology.clab.yml --reconfigure

clean:
	containerlab destroy --topo topology.clab.yml --cleanup 2>/dev/null || true
	rm -rf clab-netforge-a3/

test:
	python3 -m pytest tests/ -v --tb=short --junitxml=test-results.xml

baseline:
	docker exec clab-netforge-a3-gateway nft -f /etc/nftables.conf

collect:
	bash scripts/collect-state.sh

destroy: clean
