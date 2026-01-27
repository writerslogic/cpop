# Makefile for Witnessd Input Method (macOS)
#
# This builds the witnessd IME as a macOS Input Method bundle.
# The bundle can be installed to ~/Library/Input Methods/

.PHONY: all clean install uninstall

# Bundle configuration
BUNDLE_NAME = Witnessd.app
BUNDLE_ID = com.witnessd.inputmethod
BUNDLE_DIR = $(BUNDLE_NAME)/Contents

# Build directories
BUILD_DIR = build
MACOS_DIR = $(BUNDLE_DIR)/MacOS
RESOURCES_DIR = $(BUNDLE_DIR)/Resources

# Go build flags for cgo
CGO_ENABLED = 1
GOFLAGS = -buildmode=c-archive

# Compiler flags
CC = clang
OBJC_FLAGS = -fobjc-arc -fmodules
FRAMEWORKS = -framework Cocoa -framework InputMethodKit -framework Carbon

# Source files
GO_SOURCES = main_darwin.go
OBJC_DIR = objc
OBJC_SOURCES = $(OBJC_DIR)/main.m $(OBJC_DIR)/WitnessdInputController.m
HEADERS = $(OBJC_DIR)/WitnessdInputController.h

all: $(BUNDLE_NAME)

# Build the Go static library
$(BUILD_DIR)/libwitnessd.a: $(GO_SOURCES)
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -buildmode=c-archive -o $@ ./

# Build the Objective-C executable
$(BUILD_DIR)/Witnessd: $(BUILD_DIR)/libwitnessd.a $(OBJC_SOURCES) $(HEADERS)
	$(CC) $(OBJC_FLAGS) $(FRAMEWORKS) \
		-I$(BUILD_DIR) \
		$(OBJC_SOURCES) \
		$(BUILD_DIR)/libwitnessd.a \
		-o $@

# Create the bundle structure
$(BUNDLE_NAME): $(BUILD_DIR)/Witnessd Info.plist
	@mkdir -p $(MACOS_DIR)
	@mkdir -p $(RESOURCES_DIR)
	cp $(BUILD_DIR)/Witnessd $(MACOS_DIR)/
	cp Info.plist $(BUNDLE_DIR)/
	@echo "Bundle created: $(BUNDLE_NAME)"

# Generate Info.plist if it doesn't exist
Info.plist:
	@echo '<?xml version="1.0" encoding="UTF-8"?>' > $@
	@echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >> $@
	@echo '<plist version="1.0">' >> $@
	@echo '<dict>' >> $@
	@echo '    <key>CFBundleDevelopmentRegion</key>' >> $@
	@echo '    <string>en</string>' >> $@
	@echo '    <key>CFBundleDisplayName</key>' >> $@
	@echo '    <string>Witnessd</string>' >> $@
	@echo '    <key>CFBundleExecutable</key>' >> $@
	@echo '    <string>Witnessd</string>' >> $@
	@echo '    <key>CFBundleIdentifier</key>' >> $@
	@echo '    <string>$(BUNDLE_ID)</string>' >> $@
	@echo '    <key>CFBundleInfoDictionaryVersion</key>' >> $@
	@echo '    <string>6.0</string>' >> $@
	@echo '    <key>CFBundleName</key>' >> $@
	@echo '    <string>Witnessd</string>' >> $@
	@echo '    <key>CFBundlePackageType</key>' >> $@
	@echo '    <string>APPL</string>' >> $@
	@echo '    <key>CFBundleShortVersionString</key>' >> $@
	@echo '    <string>1.0.0</string>' >> $@
	@echo '    <key>CFBundleVersion</key>' >> $@
	@echo '    <string>1</string>' >> $@
	@echo '    <key>LSBackgroundOnly</key>' >> $@
	@echo '    <true/>' >> $@
	@echo '    <key>LSMinimumSystemVersion</key>' >> $@
	@echo '    <string>10.15</string>' >> $@
	@echo '    <key>NSPrincipalClass</key>' >> $@
	@echo '    <string>NSApplication</string>' >> $@
	@echo '    <key>InputMethodConnectionName</key>' >> $@
	@echo '    <string>$(BUNDLE_ID)_Connection</string>' >> $@
	@echo '    <key>InputMethodServerControllerClass</key>' >> $@
	@echo '    <string>WitnessdInputController</string>' >> $@
	@echo '    <key>tsInputMethodCharacterRepertoireKey</key>' >> $@
	@echo '    <array>' >> $@
	@echo '        <string>Latn</string>' >> $@
	@echo '    </array>' >> $@
	@echo '    <key>tsInputMethodIconFileKey</key>' >> $@
	@echo '    <string>icon</string>' >> $@
	@echo '    <key>TISInputSourceID</key>' >> $@
	@echo '    <string>$(BUNDLE_ID)</string>' >> $@
	@echo '    <key>TISIntendedLanguage</key>' >> $@
	@echo '    <string>en</string>' >> $@
	@echo '</dict>' >> $@
	@echo '</plist>' >> $@

install: $(BUNDLE_NAME)
	@echo "Installing to ~/Library/Input Methods/"
	@mkdir -p ~/Library/Input\ Methods
	cp -R $(BUNDLE_NAME) ~/Library/Input\ Methods/
	@echo "Installation complete."
	@echo "Enable the input method in System Preferences > Keyboard > Input Sources"

uninstall:
	@echo "Removing from ~/Library/Input Methods/"
	rm -rf ~/Library/Input\ Methods/$(BUNDLE_NAME)
	@echo "Uninstallation complete."

clean:
	rm -rf $(BUILD_DIR) $(BUNDLE_NAME) Info.plist

# For development: build and test
dev: all
	@echo "Starting Witnessd IME in development mode..."
	./$(MACOS_DIR)/Witnessd
