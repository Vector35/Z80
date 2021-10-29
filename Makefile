.PHONY: error install uninstall

ifndef BN_PLUGINS
	$(error BN_PLUGINS is undefined)
	@exit -1
endif

error:
	@echo "available targets: install, uninstall"
	@exit -1

install:
	@if [ -L "$(BN_PLUGINS)/Z80" ]; then \
		echo "already installed"; \
	else \
		echo "installing"; \
		ln -s "$(PWD)" "$(BN_PLUGINS)/Z80"; \
	fi

uninstall:
	@if [ -L "$(BN_PLUGINS)/Z80" ]; then \
		echo "uninstalling"; \
		rm "$(BN_PLUGINS)/Z80"; \
	else \
		echo "not installed"; \
	fi

