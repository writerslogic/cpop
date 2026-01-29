# Makefile for Witnessd TSF (Windows)
#
# Builds the witnessd Text Services Framework DLL.
# Requires: Go, MSVC (cl.exe), Windows SDK

.PHONY: all clean install uninstall

DLL_NAME = witnessd.dll
LIB_NAME = witnessd.a
BUILD_DIR = build

# Go build flags
CGO_ENABLED = 1
GOOS = windows
GOARCH = amd64

# MSVC flags
CL_FLAGS = /EHsc /LD /MD /O2
LINK_FLAGS = /DLL /OUT:$(BUILD_DIR)/$(DLL_NAME)

all: $(BUILD_DIR)/$(DLL_NAME)

$(BUILD_DIR):
	mkdir $(BUILD_DIR)

# Build Go library as C archive
$(BUILD_DIR)/$(LIB_NAME): $(BUILD_DIR)
	set CGO_ENABLED=1
	set GOOS=windows
	set GOARCH=amd64
	go build -buildmode=c-archive -o $(BUILD_DIR)/$(LIB_NAME) .

# Build TSF DLL
$(BUILD_DIR)/$(DLL_NAME): $(BUILD_DIR)/$(LIB_NAME) tsf/witnessd_tsf.cpp tsf/witnessd_tsf.h
	cl $(CL_FLAGS) /I$(BUILD_DIR) tsf/witnessd_tsf.cpp $(BUILD_DIR)/$(LIB_NAME) \
		kernel32.lib user32.lib ole32.lib oleaut32.lib advapi32.lib shlwapi.lib \
		$(LINK_FLAGS)

install: $(BUILD_DIR)/$(DLL_NAME)
	@echo Installing TSF DLL...
	@echo This requires Administrator privileges.
	regsvr32 $(BUILD_DIR)/$(DLL_NAME)
	@echo.
	@echo Installation complete.
	@echo Enable Witnessd in Windows Settings ^> Time ^& Language ^> Language ^> Keyboard

uninstall:
	@echo Uninstalling TSF DLL...
	regsvr32 /u $(BUILD_DIR)/$(DLL_NAME)
	@echo Uninstallation complete.

clean:
	-rmdir /s /q $(BUILD_DIR) 2>nul
	-del /q *.obj 2>nul
	-del /q *.exp 2>nul
	-del /q *.lib 2>nul

# For cross-compilation from Linux/macOS (requires mingw-w64)
cross:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
		go build -buildmode=c-archive -o $(BUILD_DIR)/$(LIB_NAME) .
	@echo "Cross-compiled Go library. TSF DLL must be built on Windows with MSVC."
