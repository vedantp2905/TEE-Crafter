.PHONY: install test clean

install:
	rm -rf venv
	python3.11 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -e .
	./venv/bin/pip install -r requirements.txt

clean:
	rm -rf builds/
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type d -name "*.egg-info" -exec rm -r {} +
	find . -type f -name "*.pyc" -exec rm {} +
	find . -type d -name ".pytest_cache" -exec rm -r {} +
	find . -type f -name "*.DS_Store" -exec rm {} +