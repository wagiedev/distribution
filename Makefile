.PHONY: test test-registry

test:
	python3 -m unittest discover -s tests -v
	python3 -m py_compile scripts/*.py tests/*.py
	python3 scripts/check_workflows.py
	bash -n scripts/publish.sh scripts/run-actionlint.sh scripts/run-shellcheck.sh
	scripts/run-shellcheck.sh
	scripts/run-actionlint.sh

test-registry:
	WAGIE_TEST_REGISTRY=1 python3 -m unittest discover -s tests -p test_publish_images.py -v
