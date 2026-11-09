.PHONY: install data detect test demo serve all clean

install:
	pip install -r requirements.txt

data:
	python scripts/make_data.py

detect:
	python scripts/run_detect.py

test:
	python -m pytest -q

demo:
	python scripts/make_demo.py

serve:
	AW_LOG=data/sim/demo/auth.log uvicorn aw.api:app --host 127.0.0.1 --port 8000

all: data detect test

clean:
	rm -rf aw/__pycache__ tests/__pycache__ .pytest_cache
