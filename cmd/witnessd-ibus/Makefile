# Makefile for Witnessd IBus Engine (Linux)
#
# Builds the witnessd IBus input method engine.

.PHONY: all clean install uninstall test

BINARY = witnessd-ibus
INSTALL_DIR = /usr/local/bin
COMPONENT_DIR = $(HOME)/.local/share/ibus/component

all: $(BINARY)

$(BINARY):
	go build -o $(BINARY) .

test:
	go test -v ./...

install: $(BINARY)
	@echo "Installing $(BINARY) to $(INSTALL_DIR)"
	sudo install -m 755 $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "Installing IBus component..."
	./$(BINARY) -install
	@echo "Restarting IBus..."
	-ibus restart 2>/dev/null || true
	@echo ""
	@echo "Installation complete."
	@echo "Enable Witnessd in IBus preferences or GNOME Settings > Keyboard > Input Sources"

uninstall:
	@echo "Removing IBus component..."
	./$(BINARY) -uninstall 2>/dev/null || true
	@echo "Removing binary..."
	sudo rm -f $(INSTALL_DIR)/$(BINARY)
	@echo "Restarting IBus..."
	-ibus restart 2>/dev/null || true
	@echo "Uninstallation complete."

clean:
	rm -f $(BINARY)

# Development helpers
run: $(BINARY)
	./$(BINARY)

fmt:
	go fmt ./...

vet:
	go vet ./...
