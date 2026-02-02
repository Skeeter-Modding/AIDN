# AIDN XDP/eBPF Makefile
# Compiles eBPF programs for high-speed packet filtering

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# Kernel headers
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)

# Compiler flags
CLANG_FLAGS = -g -O2 -target bpf \
	-D__TARGET_ARCH_x86 \
	-I$(KERNEL_HEADERS)/include \
	-I$(KERNEL_HEADERS)/arch/x86/include \
	-I/usr/include/bpf \
	-Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types

SOURCES = aidn_xdp.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean install uninstall load unload

all: $(OBJECTS)

%.o: %.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

# Generate skeleton header for userspace
aidn_xdp.skel.h: aidn_xdp.o
	$(BPFTOOL) gen skeleton $< > $@

install: $(OBJECTS)
	@echo "Installing AIDN XDP module..."
	@mkdir -p /opt/aidn/xdp
	@cp aidn_xdp.o /opt/aidn/xdp/
	@cp loader.sh /opt/aidn/xdp/
	@chmod +x /opt/aidn/xdp/loader.sh
	@echo "XDP module installed to /opt/aidn/xdp/"

load: aidn_xdp.o
	@echo "Loading AIDN XDP program..."
	@./loader.sh load

unload:
	@echo "Unloading AIDN XDP program..."
	@./loader.sh unload

clean:
	rm -f $(OBJECTS) *.skel.h

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which $(CLANG) > /dev/null || (echo "ERROR: clang not found" && exit 1)
	@which $(BPFTOOL) > /dev/null || (echo "ERROR: bpftool not found" && exit 1)
	@test -d $(KERNEL_HEADERS) || (echo "ERROR: Kernel headers not found" && exit 1)
	@echo "All dependencies satisfied"
