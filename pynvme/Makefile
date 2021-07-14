.DEFAULT_GOAL := python

SWIG ?= swig
PYTHON ?= python3

nvme_swig := nvme.i

nvme_wrap.c: $(nvme_swig)
	$(SWIG) -python -py3 -outdir . $<

python: nvme_wrap.c setup.py
	$(PYTHON) setup.py build

#install:
#

clean:
	rm -rf nvme_wrap.c nvme.py build
