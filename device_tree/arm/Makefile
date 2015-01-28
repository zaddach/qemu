DT_SOURCE := $(wildcard *.dts)
DT_BUILD := $(DT_SOURCE:.dts=.dtb)

DTC ?= dtc

all: $(DT_BUILD)

%.dtb: %.dts
	$(DTC) -I dts -O dtb -b 0 -H both -i . -o $@ $<

.PHONY: clean
clean:
	rm -f *.dtb
