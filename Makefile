# -*- Makefile -*-

MAKEFLAGS=-w

SOURCES = gr.cc

DIST = dist
BUILD = build

CLANG = $(shell if g++ --version 2>&1 | grep -i llvm >/dev/null; then echo Y; else echo N; fi)
ifeq ($(CLANG),Y)
  WEVERYTHING = -Weverything -Wno-c++98-compat
  STD = c++14
else
  WEVERYTHING = -Wall -Wextra
  STD = c++11
endif

WARNINGS = -Wno-padded
OPTIMIZATION = -O3
CXXFLAGS = -g $(OPTIMIZATION) -std=$(STD) $(WEVERYTHING) $(WARNINGS)
LDFLAGS =
LDLIBS = -lbz2

all: $(DIST)/gr

$(DIST)/gr: $(patsubst %.cc,$(BUILD)/%.o,$(SOURCES)) | $(DIST)
	g++ $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(DIST):
	mkdir -p $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(DIST) $(BUILD)

$(BUILD)/%.o: %.cc | $(BUILD)
	g++ $(CXXFLAGS) -c -o $@ $^
