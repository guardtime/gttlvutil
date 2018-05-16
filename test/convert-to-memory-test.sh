#!/bin/bash

#
# Copyright 2013-2016 Guardtime, Inc.
#
# This file is part of the Guardtime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime, Inc., and no license to trademarks is granted; Guardtime
# reserves and retains all trademark rights.

if [ "$#" -eq 1 ]; then
	test_suite="$1"
else
	echo "Usage $0 <test_suite>"
	exit 1
fi

# Delete a text between two markers. First marker is deleted
# the second one is not.
# arg1		- first marker.
# arg2		- last marker.
# arg3		- file to modify.
function delete_from_to_1() {
	sed -i '/.*'$1'.*/{
	:loop
N
s/.*\n//g
/.*'$2'.*/!{
b loop
}
}' $3
}


# Replace the stderr regex in test file. Avoid replacment
# If there is a comment mark at the beginning of the line.
# arg1		- regex for memory test.
# arg2		- file to modify.
function insert_memory_control() {
sed -i '/>>>=/{
/#.*>>>=/!{
	/>>>=/i >>>2 '"$1"'
}
}' $2
}


echo "Prepare test suite for memory tests: $test_suite"

delete_from_to_1 '>>>2' '>>>=' $test_suite
insert_memory_control "\/((LEAK SUMMARY.*)\n(.*definitely lost.*)(.* 0 .*)(.* 0 .*)\n(.*indirectly lost.*)(.* 0 .*)(.* 0 .*)\n(.*possibly lost.*)(.* 0 .*)(.* 0 .*))|(.*All heap blocks were freed.*no leaks are possible.*)\/" $test_suite

exit $?
