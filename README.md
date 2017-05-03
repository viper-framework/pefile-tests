# pefile-tests


_pefile-tests_ is a test suite for pefile. The upstream pefile project
test data files are encrypted and not usable.

Note that the while the code itself is BSD-licensed, several PE files used
in this test suite have multiple and sometimes undefined origins.

We are trying to document where they are coming from. They are used only
for testing the pefile code.

A large number of test files are originally from https://github.com/corkami/pocs
Many thanks to @angea !


## Usage

1. Ensure that you are in a virtualenv and have pefile installed
   (either from Pypi or a local clone) 
   
2. Install pytest: `pip install pytest`

2. run the tests: `pytest tests`
