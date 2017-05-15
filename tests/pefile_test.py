# -*- coding: utf-8 -*-

# The MIT License (MIT)
#
# Copyright (c) 2004-2016 Ero Carrera
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


from __future__ import print_function

from builtins import range
import difflib
from hashlib import sha256
import os
import unittest

import pefile


REGRESSION_TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
POCS_TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'corkami/pocs')


class Test_pefile(unittest.TestCase):

    maxDiff = None

    def setUp(self):
        self.test_files = self._load_test_files()

    def _load_test_files(self):
        """Load all the test files to be processes"""

        test_files = []

        for dirpath, dirname, filenames in os.walk(REGRESSION_TESTS_DIR):
            for filename in (f for f in filenames if not f.endswith('.dmp')):
                test_files.append(os.path.join(dirpath, filename))

        for dirpath, dirname, filenames in os.walk(POCS_TESTS_DIR):
            for filename in (f for f in filenames if not f.endswith('.dmp')):
                test_files.append(os.path.join(dirpath, filename))

        return test_files

    def test_pe_image_regression_test(self):
        """Run through all the test files and make sure they run correctly"""

        for idx, pe_filename in enumerate(self.test_files):
            if pe_filename.endswith('empty_file'):
                continue

            try:
                pe = pefile.PE(pe_filename)
                pe_file_data = pe.dump_info()
                pe.dump_dict()
                pe_file_data = pe_file_data.replace('\n\r', '\n')
            except Exception as excp:
                print('Failed processing [%s]' % os.path.basename(pe_filename))
                raise

            control_data_filename = '%s.dmp' % pe_filename

            if not os.path.exists(control_data_filename):
                print((
                    'Could not find control data file [%s]. '
                    'Assuming first run and generating...') % (
                    os.path.basename(control_data_filename)))
                with open(control_data_filename, 'wb') as control_data_f:
                    control_data_f.write(pe_file_data.encode('utf-8', 'backslashreplace'))
                continue

            with open(control_data_filename, 'rb') as control_data_f:
                control_data = control_data_f.read()

            pe_file_data_hash = sha256(pe_file_data.encode('utf-8', 'backslashreplace')).hexdigest()
            control_data_hash = sha256(control_data).hexdigest()

            diff_lines_added_count = 0
            diff_lines_removed_count = 0
            lines_to_ignore = 0

            if control_data_hash != pe_file_data_hash:
                print('Hash differs for [%s]' % os.path.basename(pe_filename))

                diff = difflib.ndiff(
                    control_data.decode('utf-8').splitlines(), pe_file_data.splitlines())
                # check the diff
                for line in diff:
                    # Count all changed lines
                    if line.startswith('+ '):
                        diff_lines_added_count += 1
                        # Window's returns slightly different date strings,
                        # ignore those.
                        if 'TimeDateStamp' in line:
                            lines_to_ignore += 1
                    if line.startswith('- '):
                        diff_lines_removed_count += 1
                        # Same as before, the condition is here, in both
                        # places because we want to count only the lines in
                        # which TimeDateStamp appears that are different, the
                        # identical ones are good.
                        if 'TimeDateStamp' in line:
                            lines_to_ignore += 1

                if (diff_lines_removed_count == diff_lines_added_count and
                    lines_to_ignore ==
                        diff_lines_removed_count + diff_lines_added_count):
                    print (
                        'Differences are in TimeDateStamp formatting, '
                        'ignoring...')

                else:
                    print (
                        'Lines added: %d, lines removed: %d, lines with '
                        'TimeDateStamp: %d' % (
                        diff_lines_added_count, diff_lines_removed_count,
                        lines_to_ignore))

                    # Do the diff again to store it for analysis.
                    diff = difflib.unified_diff(
                        control_data.decode('utf-8').splitlines(), pe_file_data.splitlines())
                    error_diff_f = open('error_diff.txt', 'ab')
                    error_diff_f.write(
                        b'\n________________________________________\n')
                    error_diff_f.write(
                        'Errors for file "{0}":\n'.format(pe_filename).encode('utf-8', 'backslashreplace'))
                    error_diff_f.write(
                        '\n'.join([l for l in diff if not l.startswith(' ')]).encode('utf-8', 'backslashreplace'))
                    error_diff_f.close()
                    print('Diff saved to: error_diff.txt')

            if diff_lines_removed_count == 0:
                try:
                    self.assertEqual(control_data.decode('utf-8'), pe_file_data)
                except AssertionError:
                    diff = difflib.unified_diff(
                        control_data.decode('utf-8').splitlines(), pe_file_data.splitlines())
                    raise AssertionError('\n'.join(diff))

            os.sys.stdout.write('[%d]' % (len(self.test_files) - idx))
            os.sys.stdout.flush()


    def test_selective_loading_integrity(self):
        """Verify integrity of loading the separate elements of the file as
        opposed to do a single pass.
        """

        control_file = os.path.join(REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        pe = pefile.PE(control_file, fast_load=True)
        # Load the 16 directories.
        pe.parse_data_directories(directories=list(range(0x10)))

        # Do it all at once.
        pe_full = pefile.PE(control_file, fast_load=False)

        # Verify both methods obtained the same results.
        self.assertEqual(pe_full.dump_info(), pe.dump_info())

        pe.close()
        pe_full.close()

    def test_imphash(self):
        """Test imphash values."""

        self.assertEqual(
            pefile.PE(os.path.join(
                REGRESSION_TESTS_DIR, 'mfc40.dll')).get_imphash(),
            'b0f969ff16372d95ef57f05aa8f69409')

        self.assertEqual(
            pefile.PE(os.path.join(
                REGRESSION_TESTS_DIR, 'kernel32.dll')).get_imphash(),
            '437d147ea3f4a34fff9ac2110441696a')

        self.assertEqual(
            pefile.PE(os.path.join(
                REGRESSION_TESTS_DIR, 'cmd.exe')).get_imphash(),
            'd0058544e4588b1b2290b7f4d830eb0a')

    def test_write_header_fields(self):
        """Verify correct field data modification."""

        # Test version information writing
        control_file = os.path.join(REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        pe = pefile.PE(control_file, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        original_data = pe.write()

        str1 = b'string1'
        str2 = b'str2'
        str3 = b'string3'

        pe.FileInfo[0].StringTable[0].entries['FileDescription'] = str1
        pe.FileInfo[0].StringTable[0].entries['FileVersion'] = str2
        pe.FileInfo[0].StringTable[0].entries['InternalName'] = str3

        new_data = pe.write()

        diff, differences = 0, list()
        for idx in range(len(original_data)):
            if original_data[idx] != new_data[idx]:

                diff += 1
                # Skip the zeroes that pefile automatically adds to pad a new,
                # shorter string, into the space occupied by a longer one.
                if new_data[idx] != 0:
                    differences.append(chr(new_data[idx]))

        # Verify all modifications in the file were the ones we just made
        #
        self.assertEqual(''.join(differences).encode('utf-8', 'backslashreplace'), str1 + str2 + str3)

        pe.close()

    def test_nt_headers_exception(self):
        """pefile should fail parsing invalid data (missing NT headers)"""

        # Take a known good file.
        control_file = os.path.join(REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        pe = pefile.PE(control_file, fast_load=True)

        # Truncate it at the PE header and add invalid data.
        pe_header_offest = pe.DOS_HEADER.e_lfanew
        corrupted_data = pe.__data__[:pe_header_offest] + b'\0' * (1024 * 10)

        self.assertRaises(pefile.PEFormatError, pefile.PE, data=corrupted_data)


    def test_dos_header_exception_large_data(self):
        """pefile should fail parsing 10KiB of invalid data
        (missing DOS header).
        """

        # Generate 10KiB of zeroes
        data = b'\0' * (1024 * 10)

        # Attempt to parse data and verify PE header, a PEFormatError exception
        # is thrown.
        self.assertRaises(pefile.PEFormatError, pefile.PE, data=data)


    def test_dos_header_exception_small_data(self):
        """pefile should fail parsing 64 bytes of invalid data
        (missing DOS header).
        """

        # Generate 64 bytes of zeroes
        data = b'\0' * (64)

        # Attempt to parse data and verify PE header a PEFormatError exception
        # is thrown.
        self.assertRaises(pefile.PEFormatError, pefile.PE, data=data)


    def test_empty_file_exception(self):
        """pefile should fail parsing empty files."""

        # Take a known good file
        control_file = os.path.join(REGRESSION_TESTS_DIR, 'empty_file')
        self.assertRaises(pefile.PEFormatError, pefile.PE, control_file)

    def test_relocated_memory_mapped_image(self):
        """Test different rebasing methods produce the same image"""

        # Take a known good file
        control_file = os.path.join(REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        pe = pefile.PE(control_file)

        def count_differences(data1, data2):
            diff = 0
            for idx in range(len(data1)):
                if data1[idx] != data2[idx]:
                    diff += 1
            return diff

        original_image_1 = pe.get_memory_mapped_image()
        rebased_image_1 = pe.get_memory_mapped_image(ImageBase=0x1000000)

        differences_1 = count_differences(original_image_1, rebased_image_1)
        self.assertEqual(differences_1,  61136)

        original_image_2 = pe.get_memory_mapped_image()
        pe.relocate_image(0x1000000)
        rebased_image_2 = pe.get_memory_mapped_image()

        differences_2 = count_differences(original_image_2, rebased_image_2)
        self.assertEqual(differences_2, 61136)

        # Ensure the original image stayed the same
        self.assertEqual(original_image_1, original_image_2)

    def test_checksum(self):
        """Verify correct calculation of checksum"""

        # Take a known good file.
        control_file = os.path.join(REGRESSION_TESTS_DIR, 'MSVBVM60.DLL')
        pe = pefile.PE(control_file)

        # verify_checksum() generates a checksum from the image's data and
        # compares it against the checksum field in the optional header.
        self.assertEqual(pe.verify_checksum(), True)
