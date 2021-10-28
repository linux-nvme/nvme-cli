.DEFAULT_GOAL := python

SWIG ?= swig
PYTHON ?= python3

prefix ?= /usr

nvme_swig := nvme.i

nvme_wrap.c: $(nvme_swig)
	$(SWIG) -python -py3 -outdir . $<

python: nvme_wrap.c setup.py
	$(PYTHON) setup.py build

install:
	$(PYTHON) setup.py install --prefix=$(prefix)

clean:
	rm -rf nvme_wrap.c nvme.py build
