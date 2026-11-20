PY ?= python
export PYTHONPATH := src
export MPLBACKEND := Agg

.PHONY: test demo eval sweep figures check

test:
	$(PY) -m unittest discover -s tests -v

demo:
	$(PY) -m mutation_bandit.cli demo --target tlv --scheduler repair_ctl --execs 5000

eval:
	$(PY) -m mutation_bandit.cli bench --execs 20000 --seeds 1 2 3 4 5 6 --out results/results.json

sweep:
	$(PY) scripts/admission_sweep.py

figures:
	$(PY) scripts/make_figures.py

check:
	$(PY) scripts/check_repro.py
