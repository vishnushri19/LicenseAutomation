.PHONY: setup dossier activate

setup:
	python3 -m venv .venv
	. .venv/bin/activate && python -m pip install --upgrade pip
	. .venv/bin/activate && pip install -r requirements.txt

dossier:
	@test -n "$$BIGIP_HOST" || (echo "ERROR: BIGIP_HOST is not set"; exit 2)
	@test -n "$$BIGIP_USER" || (echo "ERROR: BIGIP_USER is not set"; exit 2)
	@test -n "$$F5_REGISTRATION_KEY" || (echo "ERROR: F5_REGISTRATION_KEY is not set"; exit 2)
	. .venv/bin/activate && python scripts/license_bigip.py

activate:
	@test -n "$$BIGIP_HOST" || (echo "ERROR: BIGIP_HOST is not set"; exit 2)
	@test -n "$$BIGIP_USER" || (echo "ERROR: BIGIP_USER is not set"; exit 2)
	@test -n "$$F5_REGISTRATION_KEY" || (echo "ERROR: F5_REGISTRATION_KEY is not set"; exit 2)
	. .venv/bin/activate && python scripts/license_bigip.py --activate
