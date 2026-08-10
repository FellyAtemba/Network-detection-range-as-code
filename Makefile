.PHONY: lab clean test build baseline collect destroy

CLAB = docker run --rm --privileged --net=host --pid=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /home/at3mba/soc-stage7:/home/at3mba/soc-stage7 \
  -v /home/at3mba/.local/bin/containerlab:/usr/local/bin/containerlab \
  -w /home/at3mba/soc-stage7 \
  alpine:3.20 /usr/local/bin/containerlab

build:
	docker build -t soc-gateway:latest configs/gateway/
	docker build -t soc-host:latest services/host/

lab: build
	python3 scripts/build_configs.py
	$(CLAB) deploy --topo topology.clab.yml --reconfigure

clean:
	$(CLAB) destroy --topo topology.clab.yml --cleanup 2>/dev/null || true
	docker run --rm --privileged -v /home/at3mba/soc-stage7:/work alpine:3.20 rm -rf /work/clab-netforge-a3/

test:
	python3 -m pytest tests/ -v --tb=short --junitxml=test-results.xml

baseline:
	docker exec clab-netforge-a3-gateway nft -f /etc/nftables.conf

collect:
	bash scripts/collect-state.sh

destroy: clean
