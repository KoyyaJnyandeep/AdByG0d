.PHONY: release-check release-archive check-archive dev-check

release-check:
	bash scripts/release_check.sh

release-archive:
	bash scripts/release.sh

check-archive:
	@ARCHIVE=$$(ls -t adbygod-*.tar.gz 2>/dev/null | head -1); \
	if [ -z "$$ARCHIVE" ]; then echo "No archive found. Run: make release-archive"; exit 1; fi; \
	bash scripts/check_release_archive.sh "$$ARCHIVE"

dev-check:
	bash scripts/dev/check.sh
