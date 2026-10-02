obj-m += op13_integrity.o

KDIR ?= /path/to/kernel
ARCH ?= arm64
CROSS_COMPILE ?=

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
