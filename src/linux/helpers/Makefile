top_srcdir := ../../..
releng := $(top_srcdir)/releng

BUILDDIR ?= $(top_srcdir)/build
MESON ?= $(releng)/meson/meson.py

ifdef FRIDA_HOST
host_machine := $(FRIDA_HOST)
else
host_machine := $(shell basename $$(ls -1 $(BUILDDIR)/frida-linux-*.txt | tail -1) | cut -d"." -f1 | cut -d"-" -f2-)
endif
host_arch := $(shell echo $(host_machine) | cut -d"-" -f2)

crossfile := $(BUILDDIR)/frida-$(host_machine).txt

artifacts_dir := artifacts
native_outdir := $(artifacts_dir)/native/$(host_arch)
bpf_outdir := $(artifacts_dir)/bpf

build-native: ext/linux/tools/include/nolibc/nolibc.h
	rm -rf build
	$(MESON) setup --cross-file $(crossfile) -Db_lto=true build
	$(MESON) compile -C build
	install -m644 build/bootstrapper.bin $(native_outdir)/bootstrapper.bin
	install -m644 build/loader.bin $(native_outdir)/loader.bin
	[ -f build/zymbiote.bin ] && install -m644 build/zymbiote.bin $(native_outdir)/zymbiote.bin || true

build-bpf: \
	$(bpf_outdir)/noarch-big/activity-sampler.elf \
	$(bpf_outdir)/noarch-big/syscall-tracer.elf \
	$(bpf_outdir)/noarch-little/activity-sampler.elf \
	$(bpf_outdir)/noarch-little/syscall-tracer.elf \
	$(bpf_outdir)/x86/syscall-tracer.elf \
	$(bpf_outdir)/x86_64/syscall-tracer.elf \
	$(bpf_outdir)/arm/syscall-tracer.elf \
	$(bpf_outdir)/armbe8/syscall-tracer.elf \
	$(bpf_outdir)/arm64/syscall-tracer.elf \
	$(bpf_outdir)/arm64be/syscall-tracer.elf \
	$(bpf_outdir)/mips/syscall-tracer.elf \
	$(bpf_outdir)/mipsel/syscall-tracer.elf \
	$(bpf_outdir)/mips64/syscall-tracer.elf \
	$(bpf_outdir)/mips64el/syscall-tracer.elf \
	$(NULL)

define declare-bpf-noarch-rule
$(bpf_outdir)/noarch-$1/%.elf: %.bpf.c
	rm -rf build
	mkdir build
	clang -O2 -g0 -target $2 -c $< -o build/module.o
	llvm-strip --strip-debug --strip-unneeded build/module.o
	install -m644 build/module.o $@
endef

define declare-bpf-arch-rule
$(bpf_outdir)/$1/%.elf: %.bpf.c
	rm -rf build
	mkdir build
	python3 $(top_srcdir)/lib/base/linux-syscalls/generate-bindings.py \
		--abi $1 \
		--out-c-header build/frida-linux-syscalls.h
	clang -O2 -g0 -target $2 -c $$< -o build/module.o
	llvm-strip --strip-debug --strip-unneeded build/module.o
	mkdir -p $$(@D)
	install -m644 build/module.o $$@
endef

$(eval $(call declare-bpf-noarch-rule,big,bpfeb))
$(eval $(call declare-bpf-noarch-rule,little,bpfel))

$(eval $(call declare-bpf-arch-rule,x86,bpfel))
$(eval $(call declare-bpf-arch-rule,x86_64,bpfel))
$(eval $(call declare-bpf-arch-rule,arm,bpfel))
$(eval $(call declare-bpf-arch-rule,armbe8,bpfeb))
$(eval $(call declare-bpf-arch-rule,arm64,bpfel))
$(eval $(call declare-bpf-arch-rule,arm64be,bpfeb))
$(eval $(call declare-bpf-arch-rule,mips,bpfeb))
$(eval $(call declare-bpf-arch-rule,mipsel,bpfel))
$(eval $(call declare-bpf-arch-rule,mips64,bpfeb))
$(eval $(call declare-bpf-arch-rule,mips64el,bpfel))

ext/linux/tools/include/nolibc/nolibc.h: nolibc-tweaks.patch
	if [ -d ext/linux ]; then \
		cd ext/linux; \
		git reset --hard; \
		git checkout v6.2; \
	else \
		git clone --branch=v6.2 --depth=1 https://github.com/torvalds/linux.git ext/linux; \
	fi
	patch -d ext/linux -p1 < nolibc-tweaks.patch
	@touch -c $@

.PHONY: build-native
