PROG ?= securid
PREFIX ?= /usr/local
DESTDIR ?=
LIBDIR ?= $(PREFIX)/lib
SYSTEM_EXTENSION_DIR ?= $(LIBDIR)/password-store/extensions
MANDIR ?= $(PREFIX)/man
BASHCOMPDIR ?= /etc/bash_completion.d

PYTHON ?= python3
SHELL := /bin/bash

all:
	@echo "pass-$(PROG) is a shell script and does not need compilation."
	@echo "Try \"make install\"."
	@echo "Requirements: pass >= 1.7, bash, python3 (stdlib only)."

# Keep the engine embedded in securid.bash in sync with securid-engine.py.
engine:
	$(PYTHON) tools/embed.py

install:
	install -d "$(DESTDIR)$(MANDIR)/man1"
	install -m 0644 pass-$(PROG).1 "$(DESTDIR)$(MANDIR)/man1/pass-$(PROG).1"
	install -d "$(DESTDIR)$(SYSTEM_EXTENSION_DIR)/"
	install -m 0755 $(PROG).bash "$(DESTDIR)$(SYSTEM_EXTENSION_DIR)/$(PROG).bash"
	install -d "$(DESTDIR)$(BASHCOMPDIR)/"
	install -m 0644 pass-$(PROG).bash.completion "$(DESTDIR)$(BASHCOMPDIR)/pass-$(PROG)"

uninstall:
	rm -vrf \
		"$(DESTDIR)$(SYSTEM_EXTENSION_DIR)/$(PROG).bash" \
		"$(DESTDIR)$(MANDIR)/man1/pass-$(PROG).1" \
		"$(DESTDIR)$(BASHCOMPDIR)/pass-$(PROG)"

lint:
	shellcheck -s bash $(PROG).bash

test:
	$(PYTHON) tools/embed.py --check
	bash tests/runtest.sh

check: lint test

.PHONY: all engine install uninstall lint test check
