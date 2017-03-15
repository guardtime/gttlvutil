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

# Temporary directory to be used for executing shell tests.
TEST_DIR=test/tmp/memory_test

# Original test suites directory.
ORIG_TEST_SUITES=test/test_suites
# Execution test suites directory.
# The orignal test suites are copied the the tmp directory, where the executable names are modified.
EXEC_TEST_SUITES=$TEST_DIR/test_suites

# Just in case cleanup before start to execute tests.
rm -rf $TEST_DIR 2> /dev/null

# Create temporary test directory.
mkdir -p $TEST_DIR

# If tlv utils are available in project directory then use those,
# otherwise use the ones installed on the machine.
if [ -f src/gttlvgrep ] &&
   [ -f src/gttlvwrap ] &&
   [ -f src/gttlvdump ] &&
   [ -f src/gttlvundump ]; then
  TLVGREP_CMD="src/gttlvgrep"
  TLVWRAP_CMD="src/gttlvwrap"
  TLVDUMP_CMD="src/gttlvdump"
  TLVUNDUMP_CMD="src/gttlvundump"
else
  TLVGREP_CMD="gttlvgrep"
  TLVWRAP_CMD="gttlvwrap"
  TLVDUMP_CMD="gttlvdump"
  TLVUNDUMP_CMD="gttlvundump"
fi

# Copy the original test suites to the temporary execution folder.
cp -r $ORIG_TEST_SUITES $EXEC_TEST_SUITES

# Convert test suites to memory tests.
for test_suite in $EXEC_TEST_SUITES/*.test; do
	test/convert-to-memory-test.sh $test_suite
done

# Prepare test cases.
sed -i -- "s|TESTCASE:||g" $EXEC_TEST_SUITES/*.test
sed -i -- "s|TESTUTIL:||g" $EXEC_TEST_SUITES/*.test
sed -i -- "s|{TEST_DIR}|$TEST_DIR|g"         $EXEC_TEST_SUITES/*.test
# Replace util names.
sed -i -- "s|{GTTLVGREP}|$TLVGREP_CMD|g"     $EXEC_TEST_SUITES/*.test
sed -i -- "s|{GTTLVWRAP}|$TLVWRAP_CMD|g"     $EXEC_TEST_SUITES/*.test
sed -i -- "s|{GTTLVDUMP}|$TLVDUMP_CMD|g"     $EXEC_TEST_SUITES/*.test
sed -i -- "s|{GTTLVUNDUMP}|$TLVUNDUMP_CMD|g" $EXEC_TEST_SUITES/*.test

# Excecute automated tests.
#shelltest -c $EXEC_TEST_SUITES -- -j1
#--error-exitcode=<number> [default: 0]
#Specifies an alternative exit code to return if Valgrind reported any errors in the run. When set to the default value (zero), the return value from Valgrind will always be the return value of the process being simulated. When set to a nonzero value, that value is returned instead, if Valgrind detects any errors. This is useful for using Valgrind as part of an automated test suite, since it makes it easy to detect test cases for which Valgrind has reported errors, just by inspecting return codes.
valgrind --leak-check=full --trace-children=yes -- shelltest -c $EXEC_TEST_SUITES
# Get execution exit code.
EXIT_CODE=$?

# Cleanup if not failed.
if [ $EXIT_CODE -eq 0 ] ; then
	rm -rf $TEST_DIR 2> /dev/null
fi

exit $EXIT_CODE
