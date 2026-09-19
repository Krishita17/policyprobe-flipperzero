# PolicyProbe — reproducible pipeline targets.
# Every figure, table and report in this repository is produced by one of these.

PY ?= .venv/bin/python
PIP ?= .venv/bin/pip
PROBE = $(PY) -m policyprobe.cli

.DEFAULT_GOAL := help
.PHONY: help setup validate data scan scan-real map report evaluate figures tables all test clean

help:            ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup:           ## Create the virtualenv and install dependencies
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

validate:        ## Check the control mapping knowledge base for dangling references
	$(PROBE) validate

data:            ## Generate the synthetic facility profile
	$(PROBE) data

scan:            ## Probe the facility with the hardware-free mock backend
	$(PROBE) scan --backend mock

scan-real:       ## Probe with a real Flipper Zero (set PORT=/dev/tty.usbmodemflip_XXXX)
	$(PROBE) scan --backend flipper-cli --port $(PORT)

map:             ## Map findings onto ISO 27001 and NIST 800-53 controls
	$(PROBE) map

evaluate:        ## Score detection, control assignment and posture ordering
	$(PROBE) evaluate

figures:         ## Regenerate every figure
	$(PROBE) figures

tables:          ## Regenerate the README tables from the knowledge base
	$(PROBE) tables

report:          ## Write the compliance report (Markdown + HTML)
	$(PROBE) report

all:             ## Run the whole pipeline end to end
	$(PROBE) all

test:            ## Run the test suite
	$(PY) -m pytest -q

clean:           ## Remove generated artefacts (keeps committed samples)
	rm -rf results/*.json results/*.csv results/tables data/synthetic
	rm -f figures/*.png figures/*.mmd reports/sample_compliance_report.*
