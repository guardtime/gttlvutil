#
# GUARDTIME CONFIDENTIAL
#
# Copyright (C) [2015] Guardtime, Inc
# All Rights Reserved
#
# NOTICE:  All information contained herein is, and remains, the
# property of Guardtime Inc and its suppliers, if any.
# The intellectual and technical concepts contained herein are
# proprietary to Guardtime Inc and its suppliers and may be
# covered by U.S. and Foreign Patents and patents in process,
# and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this
# material is strictly forbidden unless prior written permission
# is obtained from Guardtime Inc.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime Inc.
#

!IFNDEF RTL
RTL = MT
!MESSAGE Setting C Runtime Lib to MT
!ELSE IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
!ERROR RTL can only have one of the following values "MT", "MTd", "MD" or "MDd", but it is "$(RTL)". Default valu is "MT".
!ENDIF

!IF "$(INSTALL_MACHINE)" != "32" && "$(INSTALL_MACHINE)" != "64"
!ERROR set INSTALL_MACHINE=32 or INSTALL_MACHINE=64
!ENDIF

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

TOOL_NAME = gttlvdump

TOOL_OBJ = \
	$(OBJ_DIR)\tlvdump.obj \
	$(OBJ_DIR)\getopt.obj \
	$(OBJ_DIR)\fast_tlv.obj \
	$(OBJ_DIR)\desc.obj \
	$(OBJ_DIR)\dir.obj
	
TLV_CREATE_OBJ = \
	$(OBJ_DIR)\tlvcreate.obj \
	$(OBJ_DIR)\getopt.obj
	
#Compiler and linker configuration


EXT_LIB = user32.lib gdi32.lib
	
	
CCFLAGS = /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /I$(SRC_DIR) 
LDFLAGS = /NOLOGO

!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF

!IFDEF DESC_DIR
CCFLAGS = $(CCFLAGS) /DDATA_DIR=\"$(DESC_DIR)\"
!ENDIF

#Making
 

default: $(BIN_DIR)\$(TOOL_NAME).exe $(BIN_DIR)\tlvcreate.exe



$(BIN_DIR)\$(TOOL_NAME).exe: $(BIN_DIR) $(OBJ_DIR) $(TOOL_OBJ)
	link $(LDFLAGS) /OUT:$@ $(TOOL_OBJ)
	for %I in ($(SRC_DIR)\ksi.desc $(SRC_DIR)\logsig.desc) do copy %I $(BIN_DIR)\ /Y

$(BIN_DIR)\tlvcreate.exe: $(BIN_DIR) $(OBJ_DIR) $(TLV_CREATE_OBJ)
	link $(LDFLAGS) /OUT:$@ $(TLV_CREATE_OBJ) 

{$(SRC_DIR)\}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<




#Folder factory	
	
$(OBJ_DIR) $(BIN_DIR):
	@if not exist $@ mkdir $@


installer:$(BIN_DIR) $(OBJ_DIR) $(BIN_DIR)\$(TOOL_NAME).exe
!IF [candle.exe > nul] != 0
!MESSAGE Please install WiX to build installer.
!ELSE
	cd windows
	candle.exe $(TOOL_NAME).wxs -o ..\$(OBJ_DIR)\$(TOOL_NAME).wixobj -dVersion="1.0.0" -dName=$(TOOL_NAME) -dtoolName=$(BIN_DIR)\$(TOOL_NAME).exe -darch=$(INSTALL_MACHINE)
	light.exe ..\$(OBJ_DIR)\$(TOOL_NAME).wixobj -o ..\$(BIN_DIR)\$(TOOL_NAME) -pdbout ..\$(BIN_DIR)\$(TOOL_NAME).wixpdb -cultures:en-us -ext WixUIExtension
	cd ..
!ENDIF

clean:
	@for %i in ($(OBJ_DIR) $(BIN_DIR)) do @if exist .\%i rmdir /s /q .\%i
	
