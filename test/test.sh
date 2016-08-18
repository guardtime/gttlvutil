#!/bin/bash

#
# GUARDTIME CONFIDENTIAL
#
# Copyright (C) [2016] Guardtime, Inc
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

# Remove test temporary directory.  
rm -rf test/tmp 2> /dev/null

# Create test temporary directory.
mkdir -p test/tmp

# Run test suites.
shelltest -c \
	test/test_suites/dump.test \
	test/test_suites/undump.test \
	test/test_suites/grep.test \
	test/test_suites/wrap.test \
	test/test_suites/integration.test \
	test/test_suites/undump_hmac.test \
-- -j1

exit_code=$?

# Cleanup.  
rm -rf test/tmp 2> /dev/null

exit $exit_code