# gratis https://stackoverflow.com/questions/714100/os-detecting-makefile
ifeq ($(OS),Windows_NT)
    ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
        PROTOC_PLATFORM := win64
    else
        ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
            PROTOC_PLATFORM := win64
        else ifeq ($(PROCESSOR_ARCHITECTURE),x86)
            PROTOC_PLATFORM := win32
        endif
    endif
    ifndef PROTOC_PLATFORM
        $(error unsupported platform $(PROCESSOR_ARCHITEW6432):$(PROCESSOR_ARCHITECTURE))
    endif
else
    UNAME_S := $(shell uname -s)
    UNAME_M := $(shell uname -m)
    ifeq ($(UNAME_S),Linux)
        ifeq ($(UNAME_M),x86_64)
            PROTOC_PLATFORM := linux-x86_64
        else ifneq ($(filter %86,$(UNAME_M)),)
            PROTOC_PLATFORM := linux-x86_32
        endif
    else ifeq ($(UNAME_S),Darwin)
        ifeq ($(UNAME_M),arm64)
            PROTOC_PLATFORM := osx-aarch_64
        else ifeq ($(findstring 64,$(UNAME_M)),64)
            PROTOC_PLATFORM := osx-x86_64
       endif
   endif
   ifndef PROTOC_PLATFORM
       $(error unsupported platform $(UNAME_S):$(UNAME_M))
   endif
endif
