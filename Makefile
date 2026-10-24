# Tests run on Go 1.26 (the T-Pot image builder version). Uses Docker when
# available, otherwise a local toolchain at GO126 (default ~/.local/go1.26.4/bin/go).
GO126 ?= $(HOME)/.local/go1.26.4/bin/go

.PHONY: test
test:
	@if command -v docker >/dev/null 2>&1; then \
	  docker run --rm -v "$(CURDIR)":/src -w /src golang:1.26.4-alpine go test ./... ; \
	else \
	  $(GO126) test ./... ; \
	fi
