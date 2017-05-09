# gttlvutil TEST-README

This document describes how to configure and run `gttlvutil` automated test. Also the dependencies and brief overview of files related to the tests will be described.

Tests can be run with `gttlvutil` package installed on the machine, or within the project directory. On Unix platform executables are located in `src` directory. If the executables are present in the project directory then the tests are run with the corresponding binaries, otherwise the installed binaries are used.

Unit tests are using default description files. In case the project has been built without explicit setup of `--with-data-dir` option:
- via `rebuild.sh` script, then the files are loaded from `src` directory.
- via `rebuild-rpm.sh` script, then the files are loaded from default system
directory (e.g. `/usr/share/gttlvutil`).


## DEPENDENCIES

* `shelltestrunner` - mandatory for every test.


## TEST RELATED FILES

All files related to the tests can be found from directory `test` that is located in `gttlvutil` root directory.

```
resource        - directory containing all test resource files
                  (e.g. signatures, server responses);
test_suites     - directory containing all test suites;
test.sh         - use to run tests on Unix platform.
```


## CONFIGURING TESTS

No extra configuration needs to be done prior to execution of test script.


## RUNNING TESTS

Tests must be run from `gttlvutil` root directory, by executing `test.sh` script found in `test` folder to ensure that test environment is configured properly. The exit code is `0` on success and `1` on failure.

To run tests on RHEL/CentOS:

```
test/test.sh
```
