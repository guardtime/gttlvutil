@ECHO OFF
GOTO copyrightend

	GUARDTIME CONFIDENTIAL

	Copyright (C) [2016] Guardtime, Inc
	All Rights Reserved

	NOTICE:  All information contained herein is, and remains, the
	property of Guardtime Inc and its suppliers, if any.
	The intellectual and technical concepts contained herein are
	proprietary to Guardtime Inc and its suppliers and may be
	covered by U.S. and Foreign Patents and patents in process,
	and are protected by trade secret or copyright law.
	Dissemination of this information or reproduction of this
	material is strictly forbidden unless prior written permission
	is obtained from Guardtime Inc.
	"Guardtime" and "KSI" are trademarks or registered trademarks of
	Guardtime Inc.

:copyrightend

CALL "%ProgramW6432%\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /x64

ECHO ************ Rebuilding project (Win64) ************

SET OPENSSL_DIR=C:\Work\openssl

nmake clean
nmake INSTALL_MACHINE=64 HASH_PROVIDER=HASH_OPENSSL

pause
