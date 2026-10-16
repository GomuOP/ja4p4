# ja4p4: JA4+ fingerprinting in a P4 switch
#
#   make build      compile p4/main.p4 for BMv2 (build/main.json, build/main.p4info.txtpb)
#   make compare    replay FoxIO's sample captures through switch + controller, compare with the references
#   make test       the tests: JA4L known gaps, two fingerprints in one packet, identical messages close together,
#                   the JA4D6 domain flag, lists at and past their capacity, split / reorder (TLS, HTTP)
#   make live       (root) the live h1 -- s1 -- h2 run in Mininet: sudo env PYTHONPATH="$PYTHONPATH" make live
#   make docs       build docs/design.pdf and docs/detailed_architecture.pdf (both include the shared
#                   docs/problems.tex and docs/results_*.tex)
#   make clean

P4C     ?= p4c
CAPTURES ?= $(HOME)/ja4/pcap
P4_SRC  := $(wildcard p4/*.p4)

.PHONY: build compare test live docs clean

build: build/main.json

build/main.json: $(P4_SRC)
	@mkdir -p build
	$(P4C) --target bmv2 --arch v1model --p4runtime-files build/main.p4info.txtpb -o build p4/main.p4

compare: build
	python3 -u -m tools.compare --out results/compare.json

test: build
	python3 -m unittest tests.test_ja4l_gaps tests.test_one_digest_per_packet tests.test_identical_digests \
	                    tests.test_dhcp6_fqdn tests.test_capacity_limits tests.test_split_reorder \
	                    tests.test_server_flight_reorder tests.test_port_reuse tests.test_keepalive_reorder \
	                    tests.test_controller_state tests.test_vlan_and_ssh_port

live: build
	python3 network/run_live.py
	python3 tools/live_tex.py

docs: docs/design.pdf docs/detailed_architecture.pdf

docs/%.pdf: docs/%.tex docs/*.tex docs/arch/*.tex
	cd docs && xelatex -interaction=nonstopmode -halt-on-error $*.tex >/dev/null && \
	           xelatex -interaction=nonstopmode -halt-on-error $*.tex >/dev/null
	@echo "$@"

clean:
	rm -rf build docs/*.aux docs/*.log docs/*.out docs/*.toc
