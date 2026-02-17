# Build settings (override on command line, e.g. `make CXX=clang++`)
CXX ?= g++

# Project layout
SRC := Encryption/Encryption/Encryption.cpp
BUILD_DIR := build

# Output name
ifeq ($(OS),Windows_NT)
EXE := .exe
else
EXE :=
endif

TARGET := $(BUILD_DIR)/Encryption$(EXE)

# Release + highly optimized + C++23
WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wformat=2
MARCH ?= -march=native

CXXFLAGS ?=
CXXFLAGS += -std=c++23 -O3 -DNDEBUG -flto $(MARCH) $(WARNINGS)

# Ensure the sha-512 header can be found via the existing relative include
CPPFLAGS ?=
CPPFLAGS += -IEncryption/include

LDFLAGS ?=
LDFLAGS += -flto

# Windows-friendly mkdir/clean/run
ifeq ($(OS),Windows_NT)
MKDIR_P := if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
CLEAN_CMD := if exist "$(BUILD_DIR)" rmdir /S /Q "$(BUILD_DIR)"
RUN_CMD := $(BUILD_DIR)\Encryption$(EXE)
else
MKDIR_P := mkdir -p "$(BUILD_DIR)"
CLEAN_CMD := rm -rf "$(BUILD_DIR)"
RUN_CMD := ./$(TARGET)
endif

.PHONY: all run clean

all: $(TARGET)

$(BUILD_DIR):
	$(MKDIR_P)

$(TARGET): $(SRC) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

run: $(TARGET)
	$(RUN_CMD)

clean:
	$(CLEAN_CMD)
