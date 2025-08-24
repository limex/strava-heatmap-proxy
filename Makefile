SERVICE_NAME := strava-heatmap-proxy
EXTENSION_NAME := strava-cookie-exporter
INSTALL_PREFIX := $(HOME)/.local
LOCAL_BUILD_DIR := ./build

OUTPUT := \
	$(SERVICE_NAME) \
	$(EXTENSION_NAME).zip

.PHONY: all clean install uninstall install-local install-system uninstall-local uninstall-system

all: $(OUTPUT)

$(SERVICE_NAME):
	go build $@.go

$(EXTENSION_NAME).zip:
	7z a $@ ./$(EXTENSION_NAME)/*

clean:
	rm -f $(OUTPUT)
	rm -rf $(LOCAL_BUILD_DIR)

install:
	@mkdir -p $(LOCAL_BUILD_DIR)
	go build -o $(LOCAL_BUILD_DIR)/$(SERVICE_NAME) $(SERVICE_NAME).go

install-system:
	@mkdir -p $(INSTALL_PREFIX)/bin
	go build -o $(INSTALL_PREFIX)/bin/$(SERVICE_NAME) $(SERVICE_NAME).go

install-local:
	@mkdir -p $(LOCAL_BUILD_DIR)
	go build -o $(LOCAL_BUILD_DIR)/$(SERVICE_NAME) $(SERVICE_NAME).go

uninstall:
	rm -f $(INSTALL_PREFIX)/bin/$(SERVICE_NAME)
	rm -f $(LOCAL_BUILD_DIR)/$(SERVICE_NAME)

uninstall-system:
	rm -f $(INSTALL_PREFIX)/bin/$(SERVICE_NAME)

uninstall-local:
	rm -f $(LOCAL_BUILD_DIR)/$(SERVICE_NAME)
