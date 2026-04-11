#!/usr/bin/env python
# -*- coding: utf-8 -*-
#   Copyright (c) 2025 Huawei Device Co., Ltd.
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import argparse
import logging
import os
import sys
import re
import shutil
import subprocess
import time
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

try:
    import hiperf_utils
except ImportError:
    print("Error: Cannot import hiperf_utils. Please run this script in the script directory.")
    sys.exit(1)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(levelname)s: %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

log_file_handler = None

LOG_SEPARATOR_LENGTH = 60
BATCH_SIZE = 500
THREAD_POOL_INDEX_WORKERS = 8
THREAD_POOL_ANNOTATE_WORKERS = 8
SYMBOLIZER_TIMEOUT = 30
READELF_TIMEOUT = 10
SAFE_FUNC_NAME_MAX_LENGTH = 120
SUMMARY_SEPARATOR_LENGTH = 90
DEFAULT_DSO_SIZE_THRESHOLD = 1073741824
DISASSEMBLY_CONTEXT_BYTES = 16


class Period:
    """Period information class containing self period and accumulated period.
    
    This class tracks two types of period values:
    - period: The self period (time spent directly in This function/line)
    - acc_period: The accumulated period (total time including all callees)
    
    The accumulated period represents the total time spent in This function and all
    functions it calls, while the self period represents only the time spent directly
    in This function excluding callees.
    """
    def __init__(self, period=0, acc_period=0):
        self.period = period
        self.acc_period = acc_period

    def __iadd__(self, other):
        """Add another Period object to this one."""
        self.period += other.period
        self.acc_period += other.acc_period
        return self


class StringCache:
    """Global string cache for deduplication.
    
    This class stores unique strings and assigns each a unique integer ID.
    It's used to reduce memory usage by replacing repeated strings with integer IDs.
    """
    def __init__(self):
        self.strings = []
        self.string_to_id = {}
    
    def get_id(self, s):
        """Get or create an ID for a string.
        
        Arguments:
            s: String to cache
            
        Returns:
            Integer ID for the string
        """
        if s not in self.string_to_id:
            self.string_to_id[s] = len(self.strings)
            self.strings.append(s)
        return self.string_to_id[s]
    
    def get_string(self, string_id):
        """Get the original string from an ID.
        
        Arguments:
            string_id: Integer ID
            
        Returns:
            Original string
        """
        return self.strings[string_id]


class DsoPeriod:
    """DSO (Dynamic Shared Object) period statistics class.
    
    This class tracks period statistics for a specific DSO/shared library.
    It maintains the DSO name ID and accumulated period information.
    """
    def __init__(self, dso_name_id):
        self.dso_name_id = dso_name_id
        self.period = Period()

    def add_period(self, period):
        """Add period information to this DSO."""
        self.period += period


class FilePeriod:
    """File period statistics class.
    
    This class tracks period statistics for a specific source file.
    It maintains:
    - File ID (reference to string cache)
    - Total period for the file
    - Line-level period statistics (line_dict)
    - Function-level period statistics (function_dict)
    
    The line_dict maps line numbers to (function_name_id, start_line, Period) tuples,
    showing how much time was spent on each line of code and which function.
    """
    def __init__(self, file_id):
        self.file_id = file_id
        self.period = Period()
        self.line_dict = {}
        self.function_dict = {}

    def add_period(self, period):
        """Add period information to this file."""
        self.period += period

    def add_line_period(self, line, period, function_name_id=None, start_line=None):
        """Add period information to a specific line in this file.
        
        This method accumulates period data for individual source lines,
        allowing for hot line analysis.
        
        Arguments:
            line: Line number
            period: Period object
            function_name_id: ID of the function containing this line
            start_line: Starting line number of the function
        """
        a = self.line_dict.get(line)
        if a is None:
            self.line_dict[line] = a = [function_name_id, start_line, Period()]
        a[2] += period

    def add_function_period(self, function_name_id, function_start_line, period):
        """Add period information to a specific function in this file.
        
        This method tracks function-level statistics, associating periods
        with function name IDs and their starting line numbers.
        
        If a function with the same start_line already exists, keep the first one.
        """
        if (function_start_line is None):
            function_start_line = -1
        
        for existing_name_id, existing_data in list(self.function_dict.items()):
            if existing_data[0] == function_start_line:
                existing_data[1] += period
                return
        
        self.function_dict[function_name_id] = [function_start_line, Period()]
        self.function_dict[function_name_id][1] += period


class Symbol:
    """Symbol information class.
    
    This class represents a symbol from the profiling data, containing:
    - dso_name_id: ID of the DSO/shared library containing this symbol
    - symbol_name_id: ID of the symbol/function name
    - symbol_addr: Address of the symbol entry point
    - build_id: Build ID of the DSO for symbol validation
    """
    def __init__(self):
        self.dso_name_id = 0
        self.symbol_name_id = 0
        self.symbol_addr = 0
        self.build_id = ''


class Sample:
    """Sample data class representing a single profiling sample.
    
    This class contains information from a single profiling sample:
    - period: Number of events/period represented by this sample
    - callchain: Stack trace (list of Symbol objects)
    """
    def __init__(self):
        self.period = 0
        self.callchain = []


class DumpFileParser:
    """Dump file parser that parses perf.data.dump file format.
    
    This parser reads the text-based dump format produced by HiPerf's
    Dump command and extracts:
    - Header information (architecture, etc.)
    - Symbol information (DSO build IDs)
    - Sample data (IP, callchain, period, etc.)
    
    The dump format is a human-readable text representation of the binary
    perf.data file, making it easier to parse and debug.
    """
    def __init__(self, dump_file):
        self.dump_file = dump_file
        self.samples = []
        self.dso_build_ids = {}
        self.total_period = 0
        self.arch = 'unknown'
        self.string_cache = StringCache()

    def parse(self):
        """Parse the entire dump file.

        This method orchestrates the parsing process by:
        1. Reading all lines from the dump file
        2. Parsing header information (architecture)
        3. Parsing symbol information (DSO build IDs)
        4. Parsing sample data (callchains, periods)

        After parsing, the samples list contains all profiling samples
        with their associated symbol information.
        """
        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Parse dump file")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("  File: %s" % self.dump_file)
        
        with open(self.dump_file, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        self._parse_header(lines)
        self._parse_symbols(lines)
        self._parse_samples(lines)
        
        logger.info("  Architecture: %s" % self.arch)
        logger.info("  Samples: %d" % len(self.samples))
        logger.info("  Total period: %d" % self.total_period)

    def _parse_header(self, lines):
        """Parse file header to extract architecture information.
        
        The header contains metadata about the profiling session,
        including the CPU architecture (e.g., 'arm64', 'x86_64').
        This information is important for symbolization and addresses handling.
        """
        for line in lines:
            if line.startswith('arch:'):
                self.arch = line.split(':')[1].strip()
                break

    def _parse_symbols(self, lines):
        """Parse HIPERF_FILES_SYMBOL feature to extract DSO build ID information.
        
        This method extracts the mapping between DSO file paths and their
        build IDs. Build IDs are used to ensure that the correct version
        of a shared library is used for symbolization.
        
        The feature section format:
        feature 192:hiperf_files_symbol
        filePath:/path/to/library.so
        buildId:'abcdef123456...'
        
        Algorithm:
        1. Locate the feature section in the dump file
        2. Extract filePath and buildId pairs
        3. Store the mapping in dso_build_ids dictionary
        """
        in_symbol_section = False
        current_filepath = None
        current_build_id = None

        for i, line in enumerate(lines):
            if 'feature 192:hiperf_files_symbol' in line:
                in_symbol_section = True
                continue

            if in_symbol_section:
                if line.strip().startswith('filePath:'):
                    match = re.search(r'filePath:(.+)', line)
                    if match:
                        current_filepath = match.group(1).strip()
                        if current_filepath.startswith('[') and current_filepath.endswith(']'):
                            current_filepath = current_filepath[1:-1]
                elif line.strip().startswith("buildId:'"):
                    match = re.search(r"buildId:'([^']+)'", line)
                    if match:
                        current_build_id = match.group(1)
                        if current_filepath and current_build_id:
                            self.dso_build_ids[current_filepath] = current_build_id

                if 'feature' in line and 'hiperf_files_symbol' not in line:
                    in_symbol_section = False

    def _parse_samples(self, lines):
        """Parse sample data from the dump file.
        
        This method extracts all profiling samples, including their
        instruction pointers, callchains, and periods. Each sample
        represents one or more profiling events.
        
        Sample format:
        record sample: ip=0x... pid=... tid=... time=... cpu=... period=...
        callchain: N
        depth:addr symbol_name@[dso_name]
        ...
        
        Algorithm:
        1. Iterate through lines looking for 'record sample:' markers
        2. Parse sample metadata (ip, pid, tid, time, cpu, period)
        3. Parse the callchain following the sample
        4. Store each completed sample in the samples list
        """
        current_sample = None

        for i, line in enumerate(lines):
            if line.strip().startswith('record sample:'):
                if current_sample:
                    self.samples.append(current_sample)
                    self.total_period += current_sample.period
                current_sample = Sample()
                continue

            if current_sample:
                self._parse_sample_line(line, current_sample)
                
                if line.strip().startswith('callchain:'):
                    self._parse_callchain(lines, i, current_sample)

        if current_sample:
            self.samples.append(current_sample)
            self.total_period += current_sample.period

    def _parse_sample_line(self, line, sample):
        """Parse sample line to extract period information.
        
        This method extracts the period field from the sample line.
        
        Format:
        period 1
        """
        stripped = line.strip()

        if stripped.startswith('period '):
            parts = stripped.split()
            if len(parts) >= 2:
                sample.period = self._parse_int_value(parts[1])

    def _parse_int_value(self, value_str):
        """Parse decimal value string to integer.

        Handles values that may have trailing commas or other characters.
        """
        value_str = value_str.strip().rstrip(',')
        return int(value_str, 10)

    def _parse_callchain(self, lines, start_idx, sample):
        """Parse callchain information from the dump file.
        
        The callchain represents the stack trace at the time of sampling,
        showing the sequence of function calls that led to the sampled IP.
        
        Format:
        callchain: N
        0:0x12345678 function_name@[dso_name]
        1:0x87654321 another_function@[dso_name]
        ...
        
        Algorithm:
        1. Extract the callchain depth (N) from the callchain line
        2. Parse the next N lines as callchain entries
        3. Each entry is parsed as a Symbol object
        4. Symbols are appended to the sample's callchain list
        """
        callchain_depth = 0
        match = re.search(r'callchain:\s*(\d+)', lines[start_idx])
        if match:
            callchain_depth = int(match.group(1))

        for i in range(start_idx + 1, min(start_idx + 1 + callchain_depth, len(lines))):
            line = lines[i].strip()
            if line and not line.startswith('record'):
                symbol = self._parse_callchain_entry(line)
                if symbol:
                    sample.callchain.append(symbol)

    def _parse_callchain_entry(self, line):
        """Parse a single callchain entry to extract symbol information.
        
        Parsing steps:
        1. Split by "index:addr : body:file_offset" to extract addr
        2. Try to match body with "symbol_name[0xhex:0xhex][+0xhex]@dso_name" to extract symbol_name, dso_name
        3. If step 2 fails, try "symbol_name+0xhex@dso_name" pattern
        
        This method extracts:
        - Symbol/function name ID (if available)
        - DSO/shared library name ID
        - Symbol address (if available)
        """
        line = line.strip()
        
        pattern = r'^(\d+):0x([0-9a-fA-F]+) : (.+?):(\d+)$'
        match = re.match(pattern, line)
        if not match:
            return None
        
        try:
            addr = int(match.group(2), 16)
            body = match.group(3).strip()
        except ValueError:
            return None
        
        symbol = Symbol()
        
        pattern2 = r'^(.+?)\[(0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+)\]\[\+(0x[0-9a-fA-F]+)\]@(.+)$'
        match2 = re.match(pattern2, body)
        if match2:
            symbol_name = match2.group(1).strip()
            addr2 = match2.group(3)
            offset = match2.group(4)
            dso_name = match2.group(5).strip()
            
            symbol.symbol_name_id = self.string_cache.get_id(symbol_name)
            symbol.dso_name_id = self.string_cache.get_id(dso_name)
            
            try:
                symbol.symbol_addr = int(addr2, 16) + int(offset, 16)
            except ValueError:
                pass
        else:
            pattern3 = r'^(.+?)\+(0x[0-9a-fA-F]+)@(.+)$'
            match3 = re.match(pattern3, body)
            if match3:
                symbol_name = match3.group(1).strip()
                offset = match3.group(2)
                dso_name = match3.group(3).strip()
                
                symbol.symbol_name_id = self.string_cache.get_id(symbol_name)
                symbol.dso_name_id = self.string_cache.get_id(dso_name)
                
                try:
                    symbol.symbol_addr = int(offset, 16)
                except ValueError:
                    pass
            else:
                symbol.symbol_name_id = self.string_cache.get_id(body)
                symbol.dso_name_id = self.string_cache.get_id('')
        
        dso_name = self.string_cache.get_string(symbol.dso_name_id)
        symbol.build_id = self.dso_build_ids.get(dso_name, '')
        return symbol


class SourceFileSearcher:
    """Find source file paths in file system.
    
    This class converts abstract file paths from debug info to real source file paths
    by finding best match in provided source directories.
    
    Optimized Path Shortening Algorithm:
    1. Remove leading ../ symbols from abstract_path
    2. Try paths by progressively shortening from source_dir
    3. Return first reachable file
    4. Cache results for fast lookup
    """
    
    SOURCE_FILE_EXTS = {'.h', '.hh', '.H', '.hxx', '.hpp', '.h++',
                        '.c', '.cc', '.C', '.cxx', '.cpp', '.c++'}

    def __init__(self, source_dirs):
        self.source_dirs = source_dirs
        self._cache = {}
        self._lock = Lock()

    @classmethod
    def is_source_filename(cls, filename):
        ext = os.path.splitext(filename)[1]
        return ext in cls.SOURCE_FILE_EXTS

    def get_real_path(self, abstract_path):
        """Get real path using path shortening algorithm with caching."""
        if not abstract_path:
            return None
        
        if abstract_path in self._cache:
            return self._cache[abstract_path]
        
        result = self._search_file(abstract_path)
        
        with self._lock:
            self._cache[abstract_path] = result
        
        return result


    def _normalize_path(self, path):
        """Remove leading ../ symbols and normalize path."""
        normalized = os.path.normpath(path.replace('/', os.sep))
        parts = normalized.split(os.sep)
        
        result = []
        for part in parts:
            if part == '..':
                continue
            elif part == '.' or not part:
                continue
            else:
                result.append(part)
        
        return result
    
    def _try_path_variants(self, path_parts):
        """Try all path variants by progressively shortening."""
        for start_idx in range(len(path_parts)):
            variant_parts = path_parts[start_idx:]
            yield variant_parts
    
    def _search_file(self, abstract_path):
        """Search for file using path shortening strategy."""
        path_parts = self._normalize_path(abstract_path)
        
        if not path_parts:
            return None
        
        for source_dir in self.source_dirs:
            source_dir = os.path.normpath(source_dir)
            
            for variant_parts in self._try_path_variants(path_parts):
                candidate = os.path.join(source_dir, *variant_parts)
                
                if os.path.isfile(candidate):
                    return candidate
        
        return None
    
    def _try_path_variants(self, path_parts):
        """Try all path variants by progressively shortening."""
        for start_idx in range(len(path_parts)):
            variant_parts = path_parts[start_idx:]
            yield variant_parts
    
    def _search_file(self, abstract_path):
        """Search for file using path shortening strategy."""
        path_parts = self._normalize_path(abstract_path)
        
        if not path_parts:
            return None
        
        for source_dir in self.source_dirs:
            source_dir = os.path.normpath(source_dir)
            
            for variant_parts in self._try_path_variants(path_parts):
                candidate = os.path.join(source_dir, *variant_parts)
                
                if os.path.isfile(candidate):
                    return candidate
        
        return None


class HiperfAddr2Line:
    """Address to source code line converter, adapted from simpleperf's Addr2Nearestline algorithm.
    
    This class converts binary addresses to source file and line number information
    using LLVM's symbolization tools (llvm-symbolizer or llvm-addr2line).
    
    The Addr2Nearestline algorithm:
    1. Collect all unique addresses that need symbolization
    2. Group addresses by DSO/shared library
    3. For each DSO, locate the corresponding binary file
    4. Use llvm-symbolizer to convert addresses to source locations
    5. Cache the results for efficient lookup
    
    This approach minimizes the number of external tool invocations by
    batching addresses by DSO and using efficient caching.
    """
    def __init__(self, ndk_path, symbol_dirs, source_dirs, output_dir):
        self.ndk_path = ndk_path
        self.symbol_dirs = symbol_dirs if symbol_dirs else []
        self.source_searcher = SourceFileSearcher(source_dirs)
        self.symbolizer_path = self._find_symbolizer()
        self.addr_map = {}
        self.source_map = {}
        self.file_index = {}
        self.cache_lock = Lock()
        self.output_dir = output_dir
        self._build_file_index()

    def add_addr(self, dso_path, build_id, symbol_addr):
        """Add an addresses that needs to be converted to source line information.
        
        This method queues addresses for batch conversion. Addresses are
        grouped by DSO to optimize the symbolization process.
        
        Arguments:
            dso_path: Path to the DSO/shared library
            build_id: Build ID of the DSO (for validation)
            symbol_addr: Symbol addresses to symbolize
        """
        if dso_path not in self.addr_map:
            self.addr_map[dso_path] = {'build_id': build_id, 'addrs': set()}
        self.addr_map[dso_path]['addrs'].add(symbol_addr)

    def convert_addrs_to_lines(self, jobs=THREAD_POOL_INDEX_WORKERS, dso_size_threshold=DEFAULT_DSO_SIZE_THRESHOLD):
        """Batch convert addresses to source code lines with multithreading.

        This method performs the actual symbolization:
        1. Check if symbolizer tool is available
        2. For each DSO, convert all queued addresses in parallel
        3. Store results in source_map for later lookup

        Arguments:
            jobs: Number of threads to use for parallel processing
            dso_size_threshold: DSO size threshold in bytes (default: 1G)
                                 Skip addr2line/objdump for DSOs larger than this
        """
        if not self.symbolizer_path:
            logger.warning("llvm-symbolizer not found, skipping addresses conversion")
            return

        logger.info("  Threads: %d" % jobs)
        logger.info("  DSO threshold: %d bytes" % dso_size_threshold)

        dso_items = list(self.addr_map.items())
        total_dso = len(dso_items)
        logger.info("  Total DSOs: %d" % total_dso)
        logger.info("")
        
        counter = {'value': 0}
        counter_lock = Lock()
        skipped_large_dso = {'count': 0}
        skipped_large_dso_lock = Lock()
        
        def process_dso(dso_path, dso_info):
            with counter_lock:
                counter['value'] += 1
                current = counter['value']

            dso_name = os.path.basename(dso_path)

            binary_path = self._find_binary(dso_path)
            if binary_path and os.path.isfile(binary_path):
                file_size = os.path.getsize(binary_path)
                if file_size > dso_size_threshold:
                    with skipped_large_dso_lock:
                        skipped_large_dso['count'] += 1
                    logger.info("  [%d/%d] Skipping large DSO: %s (size: %d bytes)" %
                               (current, total_dso, dso_name, file_size))
                    return
            else:
                logger.warning("  [%d/%d] Binary not found: %s" %
                              (current, total_dso, dso_name))
                return

            addr_count = len(dso_info.get('addrs', set()))
            progress = 100.0 * current / total_dso
            start_time = time.time()
            self._convert_dso_addrs(dso_path, dso_info)
            elapsed = time.time() - start_time
            logger.info("  [%d/%d, %.1f%%] %s: %d addresses, %.2fs" %
                           (current, total_dso, progress, dso_name, addr_count, elapsed))
        
        if jobs <= 1:
            for dso_path, dso_info in dso_items:
                process_dso(dso_path, dso_info)
        else:
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = []
                for dso_path, dso_info in dso_items:
                    future = executor.submit(process_dso, dso_path, dso_info)
                    futures.append(future)
                
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error("  [ERROR] %s" % e)

        if skipped_large_dso['count'] > 0:
            logger.info("")
            logger.info("  Skipped %d large DSOs" % skipped_large_dso['count'])

    def get_sources(self, dso_path, addr):
        """Get source code line information for an addresses.
        
        This method retrieves cached symbolization results and converts
        abstract file paths to real source file paths.
        
        Arguments:
            dso_path: Path to DSO
            addr: Virtual addresses
            
        Returns:
            List of (file_path, line_num, function_name, start_line) tuples, or empty list if not found
        """
        key = (dso_path, addr)
        if key not in self.source_map:
            return []
        
        result = []
        for abstract_path, line_num, function_name, start_line in self.source_map[key]:
            real_path = self.source_searcher.get_real_path(abstract_path)
            if real_path:
                result.append((real_path, line_num, function_name, start_line))
            else:
                result.append((abstract_path, line_num, function_name, start_line))
        
        return result

    def _build_file_index(self):
        """Build file index for fast binary lookup.

        This method builds a dictionary mapping file names to their full paths
        by walking through all symbol_dirs. This enables O(1) lookup
        instead of O(N) directory traversal for each binary search.

        The indexing is done in parallel using multiple threads to speed up
        the initial indexing process.
        """
        if not self.symbol_dirs:
            return

        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Build symbol file index")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("  Symbol dirs: %d" % len(self.symbol_dirs))
        
        start_time = time.time()
        self.file_index = {}
        total_files = 0
        index_lock = Lock()

        def index_dir(symbol_dir):
            """Index files in a single directory tree."""
            local_count = 0
            for root, dirs, files in os.walk(symbol_dir):
                for file in files:
                    with index_lock:
                        if file not in self.file_index:
                            self.file_index[file] = os.path.join(root, file)
                            local_count += 1
            return local_count

        with ThreadPoolExecutor(max_workers=THREAD_POOL_INDEX_WORKERS) as executor:
            futures = [executor.submit(index_dir, d) for d in self.symbol_dirs]
            for future in as_completed(futures):
                total_files += future.result()

        elapsed = time.time() - start_time
        logger.info("  Files indexed: %d" % total_files)
        logger.info("  Time: %.2fs" % elapsed)

        if self.output_dir:
            binary_cache_path = os.path.join(self.output_dir, 'binary_cache.txt')
            with open(binary_cache_path, 'w', encoding='utf-8') as f:
                for file_name, file_path in sorted(self.file_index.items()):
                    f.write(f"{file_name} {file_path}\n")

    def _find_symbolizer(self):
        """Find llvm-symbolizer or llvm-addr2line tool.
        
        This method locates the appropriate symbolization tool:
        1. If ndk_path is provided, search directly in that directory
           (non-recursive, exact path match)
        2. If ndk_path is not provided, try system PATH
        3. Support both llvm-symbolizer and llvm-addr2line
        4. Handle Windows (.exe extension) and Unix platforms
        5. Print error message if tool cannot be found
        
        Priority order:
        - llvm-symbolizer in ndk_path (if provided)
        - llvm-addr2line in ndk_path (if provided)
        - llvm-symbolizer in system PATH
        - llvm-addr2line in system PATH
        """
        if self.ndk_path:
            for exe in ['llvm-symbolizer', 'llvm-addr2line']:
                exe_path = os.path.join(self.ndk_path, exe)
                if sys.platform == 'win32' and not exe_path.endswith('.exe'):
                    exe_path += '.exe'
                if os.path.isfile(exe_path):
                    return exe_path
            logger.error("Cannot find llvm-symbolizer or llvm-addr2line in %s" % self.ndk_path)
            return None
        
        for exe in ['llvm-symbolizer', 'llvm-addr2line']:
            if self._is_executable_available(exe):
                return exe
        
        logger.error("Cannot find llvm-symbolizer or llvm-addr2line. Please install LLVM toolchain or specify --ndk path.")
        return None
    
    def _is_executable_available(self, exe_name):
        """Check if an executable is available in the system PATH.
        
        This method attempts to run the executable with --version flag
        to verify it exists and is executable. This is more reliable than
        just checking file existence as it also verifies the tool works.
        
        Arguments:
            exe_name: Name of the executable to check
            
        Returns:
            True if the executable can be run successfully, False otherwise
        """
        try:
            result = subprocess.run([exe_name, '--version'], capture_output=True, timeout=SYMBOLIZER_TIMEOUT)
            return result.returncode == 0
        except Exception:
            return False

    def _validate_build_id(self, binary_path, expected_build_id):
        """Validate that the binary file matches the expected build ID.
        
        This method reads the build ID from the binary file and compares it
        with the expected build ID from the profiling data.
        
        Arguments:
            binary_path: Path to the binary file
            expected_build_id: Expected build ID string
            
        Returns:
            True if build IDs match or validation is skipped, False otherwise
        """
        if not expected_build_id:
            return True
        
        try:
            result = subprocess.run(['file', binary_path], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout
                if expected_build_id.lower() in output.lower():
                    return True
        except Exception:
            pass
        
        return True


    def _convert_dso_addrs(self, dso_path, dso_info):
        """Convert all addresses for a single DSO in batch.
        
        This method:
        1. Locates the binary file for the DSO
        2. Validates build_id if provided
        3. Batches all addresses to source locations in one call
        4. Caches the results in source_map
        
        Algorithm:
        - Find the binary file by searching symbol_dirs
        - Validate build_id matches the binary
        - Batch convert all addresses with _convert_addrs_batch
        - Store successful conversions in source_map[(dso_path, addr)]
        
        Arguments:
            dso_path: Path to the DSO
            dso_info: Dict with 'build_id' and 'addrs' keys
        """
        binary_path = self._find_binary(dso_path)
        if not binary_path:
            logger.warning("Binary not found for %s" % dso_path)
            return

        build_id = dso_info.get('build_id')
        if build_id and not self._validate_build_id(binary_path, build_id):
            logger.warning("Build ID mismatch for %s (expected: %s)" % (dso_path, build_id))
            return

        addr_list = list(dso_info.get('addrs', set()))
        results = self._convert_addrs_batch(binary_path, addr_list)
        
        for addr, sources in results.items():
            if sources:
                self.source_map[(dso_path, addr)] = sources

    def _find_binary(self, dso_path):
        """Find the binary file for a DSO using pre-built file index.
        
        This method uses the pre-built file index for O(1) lookup
        instead of O(N) directory traversal.
        
        Arguments:
            dso_path: Path to the DSO (may be absolute or relative)
            
        Returns:
            Full path to the binary file, or None if not found
        """
        dso_name = os.path.basename(dso_path)
        return self.file_index.get(dso_name)

    def _convert_addrs_batch(self, binary_path, addrs):
        """Convert multiple addresses to source code line information in batch.

        This method uses llvm-symbolizer or llvm-addr2line to convert
        multiple binary addresses to source file and line numbers in one call.

        Command formats:
        - llvm-symbolizer: --output-style=JSON --pretty-print --obj=<binary> --demangle --relativenames <addr1> <addr2> ...
        - llvm-addr2line: --exe=<binary> --demangle --functions <addr1> <addr2> ...

        To avoid command line length limits (especially on Windows), addresses are
        processed in batches when the number exceeds a threshold.

        Arguments:
            binary_path: Path to the binary file
            addrs: List of virtual addresses to symbolize

        Returns:
            Dict mapping addr to list of (file_path, line_num, function_name, start_line) tuples
        """
        if not self.symbolizer_path or not addrs:
            return {}

        results = {}
        
        for i in range(0, len(addrs), BATCH_SIZE):
            batch_addrs = addrs[i:i + BATCH_SIZE]
            batch_results = self._convert_addrs_batch_impl(binary_path, batch_addrs)
            results.update(batch_results)
        
        return results
    
    def _convert_addrs_batch_impl(self, binary_path, addrs):
        """Implementation of batch addresses conversion.
        
        This is the actual implementation that processes a single batch of addresses.
        """
        if not self.symbolizer_path or not addrs:
            return {}

        results = {}
        try:
            exe_name = os.path.basename(self.symbolizer_path)
            addr_strs = []
            for addr in addrs:
                addr_strs.append('0x%x' % addr)
            
            if 'addr2line' in exe_name:
                cmd = [self.symbolizer_path, '--exe=' + binary_path, '--demangle', '--functions'] + addr_strs
            else:
                cmd = [self.symbolizer_path, '--output-style=JSON', '--pretty-print', '--obj=' + binary_path, '--demangle', '--relativenames'] + addr_strs
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=SYMBOLIZER_TIMEOUT)
            if result.returncode == 0:
                results = self._parse_symbolizer_batch_output(result.stdout, addrs)
        except Exception as e:
            logger.warning("Failed to convert addresses: %s" % e)

        return results

    def _parse_symbolizer_batch_output(self, output, addrs):
        """Parse llvm-symbolizer JSON output to extract source file and line information.
        
        The JSON output format is:
        [
          {
            "Address": "0x...",
            "Symbol": [
              {
                "FunctionName": "func_name",
                "FunctionStartAddress": "0x...",
                "Line": 123,
                "FileName": "/path/to/file.cpp",
                "StartLine": 45,
                "StartFileName": "/path/to/file.cpp"
              },
              ...
            ]
          },
          ...
        ]
        
        Arguments:
            output: JSON stdout from llvm-symbolizer
            addrs: List of addresses that were requested
            
        Returns:
            Dict mapping addr to list of (file_path, line_num, function_name) tuples
        """
        results = {}
        try:
            import json
            data = json.loads(output)
            
            for item in data:
                addr_str = item.get('Address', '')
                if not addr_str:
                    continue
                
                try:
                    addr = int(addr_str, 16)
                except ValueError:
                    continue
                
                symbols = item.get('Symbol', [])
                current_sources = []
                
                for symbol in symbols:
                    function_name = symbol.get('FunctionName', '')
                    file_path = symbol.get('FileName', '')
                    line_num = symbol.get('Line', 0)
                    start_line = symbol.get('StartLine', 0)
                    
                    if file_path and line_num and function_name:
                        current_sources.append((file_path, line_num, function_name, start_line))
                
                if current_sources:
                    results[addr] = current_sources
        except Exception as e:
            logger.warning("Failed to parse JSON output: %s" % e)
        
        return results

    def _parse_source_location(self, location):
        """Parse source location string to extract file path and line number.
        
        Format: filename:line:column
        Example: /path/to/file.cpp:123:25
        
        Arguments:
            location: Source location string
            
        Returns:
            Tuple of (file_path, line_num) or (None, None) if invalid
        """
        if not location or '?' in location:
            return None, None
        
        parts = location.rsplit(':', 2)
        if len(parts) != 3:
            return None, None
        
        file_path, line_num_str, column = parts
        
        if not file_path or not line_num_str or '?' in line_num_str:
            return None, None
        
        try:
            line_num = int(line_num_str)
        except ValueError:
            return None, None
        
        return file_path, line_num


class SourceFileAnnotator:
    """Source file annotation generator.
    
    This class orchestrates the entire annotation process:
    1. Parse profiling data from dump file
    2. Collect addresses that need symbolization
    3. Convert addresses to source locations
    4. Generate period statistics for files, functions, and lines
    5. Write summary reports
    6. Annotate source files with period information
    
    The annotation adds comments to source files showing:
    - Total time spent in each file
    - Time spent on each line
    - Percentage of total execution time
    
    Algorithm for period calculation:
    - Self period: Time spent directly in This function/line
    - Accumulated period: Total time including all callees
    - For callchains, the first frame gets the full period (accumulated)
    - Subsequent frames get only self period (accumulated = 0)
    """
    def __init__(self, config, string_cache):
        self.config = config
        self.string_cache = string_cache
        self.dso_filter = set(config.get('dso_filters', []))
        
        output_dir = config.get('output_dir', 'annotated_files')
        if os.path.isdir(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)
        
        log_file_path = os.path.join(output_dir, 'run.log')
        file_handler = logging.FileHandler(log_file_path, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter('%(levelname)s: %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        output_dir = config.get('output_dir', 'annotated_files')
        self.addr2line = HiperfAddr2Line(
            config.get('ndk_path'),
            config.get('symdir', []),
            config.get('source_dirs', []),
            output_dir
        )
        self.period = 0
        self.dso_periods = {}
        self.file_periods = {}

    def annotate(self, parser, enable_disassembly=False):
        """Execute complete annotation workflow.
 
        This method performs all steps of annotation process:
        1. Collect all addresses that need symbolization
        2. Convert addresses to source file and line information
        3. Generate period statistics for all samples
        4. Write summary report with DSO, file, and line statistics
        5. Annotate source files with period comments
        6. Generate disassembly annotation (optional)
 
        Arguments:
            parser: DumpFileParser object with parsed samples
            enable_disassembly: Whether to generate disassembly annotation
        """
        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Collect addresses")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        start_time = time.time()
        self._collect_addrs(parser)
        logger.info("  Time: %.2fs" % (time.time() - start_time))

        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Convert addresses to source lines")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        start_time = time.time()
        self._convert_addrs_to_lines()
        logger.info("  Time: %.2fs" % (time.time() - start_time))

        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Generate periods")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        start_time = time.time()
        self._generate_periods(parser)
        logger.info("  Time: %.2fs" % (time.time() - start_time))

        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Write summary")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        start_time = time.time()
        self._write_period()
        logger.info("  Time: %.2fs" % (time.time() - start_time))

        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Annotate files")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        start_time = time.time()
        self._annotate_files()
        logger.info("  Time: %.2fs" % (time.time() - start_time))

        if enable_disassembly:
            logger.info("")
            logger.info("=" * LOG_SEPARATOR_LENGTH)
            logger.info("Generate disassembly")
            logger.info("=" * LOG_SEPARATOR_LENGTH)
            start_time = time.time()
            self._generate_disassembly(parser)
            logger.info("  Time: %.2fs" % (time.time() - start_time))

    def _collect_addrs(self, parser):
        """Collect all addresses that need to be converted to source lines.
        
        This method iterates through all samples and their callchains,
        collecting symbol addresses for symbolization.
        
        Algorithm:
        1. For each sample, extract the callchain
        2. For each symbol in the callchain:
           - Add the symbol addresses for symbolization
        3. Filter symbols based on dso_filter if specified
        
        This ensures we have source location information for all
        addresses in the profiling data.
        
        Arguments:
            parser: DumpFileParser containing parsed samples
        """
        for sample in parser.samples:
            if not sample.callchain:
                continue
            
            for symbol in sample.callchain:
                if self._filter_symbol(symbol):
                    dso_name = self.string_cache.get_string(symbol.dso_name_id)
                    self.addr2line.add_addr(
                        dso_name,
                        symbol.build_id,
                        symbol.symbol_addr
                    )

    def _filter_symbol(self, symbol):
        """Filter symbols based on DSO filter configuration.
        
        This method checks if a symbol should be included in the
        analysis based on the dso_filter configuration.
        
        Arguments:
            symbol: Symbol object to check
            
        Returns:
            True if the symbol should be included, False otherwise
        """
        if not self.dso_filter:
            return True
        dso_name = self.string_cache.get_string(symbol.dso_name_id)
        dso_basename = os.path.basename(dso_name)
        return dso_basename in self.dso_filter

    def _convert_addrs_to_lines(self):
        """Convert addresses to source code lines.
 
        This method triggers the symbolization process for all
        collected addresses. The results are cached in the
        HiperfAddr2Line object for later lookup.
        """
        dso_size_threshold = self.config.get('dso_size_threshold', DEFAULT_DSO_SIZE_THRESHOLD)
        self.addr2line.convert_addrs_to_lines(dso_size_threshold=dso_size_threshold)

    def _generate_periods(self, parser):
        """Generate period statistics for all samples.
        
        This method processes all samples and accumulates period
        statistics at the DSO, file, and line levels.
        
        Algorithm:
        1. For each sample, process its callchain
        2. The first frame in the callchain gets the full period
           (accumulated = period, self = 0)
        3. Subsequent frames get only self period
           (accumulated = 0, self = period)
        4. Use used_*_dict to avoid counting the same DSO/file/line
           multiple times within a single sample
        5. Accumulate periods in dso_periods, file_periods
        
        This algorithm ensures accurate attribution of execution time
        to the correct functions and lines in the callchain.
        
        Arguments:
            parser: DumpFileParser containing parsed samples
        """
        for sample in parser.samples:
            self._generate_periods_for_sample(sample)

    def _generate_periods_for_sample(self, sample):
        """Generate period statistics for a single sample.
        
        This method processes one sample's callchain and distributes
        the sample's period among the frames according to the
        accumulated vs self period semantics.
        
        Period distribution algorithm:
        - Frame 0 (leaf function): Gets full period (accumulated = period)
        - Frame 1+: Gets self period only (accumulated = 0)
        
        This ensures that:
        - The leaf function shows the total time spent in that call
        - Parent functions show only the time spent directly in them
        - The sum of self periods + accumulated periods = total time
        
        Arguments:
            sample: Sample object to process
        """
        if not sample.callchain:
            return
        
        is_sample_used = False
        used_dso_dict = {}
        used_file_dict = {}
        used_line_dict = {}
        used_function_dict = {}
        period = Period(sample.period, sample.period)
        
        for j, symbol in enumerate(sample.callchain):
            if j == 1:
                period = Period(0, sample.period)
            
            if not self._filter_symbol(symbol):
                continue
            
            is_sample_used = True
            self._add_dso_period(symbol.dso_name_id, period, used_dso_dict)
            
            dso_name = self.string_cache.get_string(symbol.dso_name_id)
            sources = self.addr2line.get_sources(dso_name, symbol.symbol_addr)
            for source in sources:
                if source:
                    file_path, line_num, function_name, start_line = source
                    file_path_id = self.string_cache.get_id(file_path)
                    function_name_id = self.string_cache.get_id(function_name) if function_name else 0
                    self._add_file_period(file_path_id, period, used_file_dict)
                    if line_num:
                        self._add_line_period(file_path_id, line_num, period, function_name_id, start_line, used_line_dict)
                    if line_num and function_name and start_line:
                        self._add_function_period(file_path_id, function_name_id, start_line, period, used_function_dict)
        
        if is_sample_used:
            self.period += sample.period

    def _add_dso_period(self, dso_name_id, period, used_dso_dict):
        """Add period statistics to a DSO.
        
        This method accumulates period information for a DSO,
        ensuring each DSO is only counted once per sample.
        
        Arguments:
            dso_name_id: ID of the DSO name
            period: Period object to add
            used_dso_dict: Dictionary tracking used DSOs in current sample
        """
        if dso_name_id not in used_dso_dict:
            used_dso_dict[dso_name_id] = True
            dso_period = self.dso_periods.get(dso_name_id)
            if dso_period is None:
                dso_period = self.dso_periods[dso_name_id] = DsoPeriod(dso_name_id)
            dso_period.add_period(period)

    def _add_file_period(self, file_path_id, period, used_file_dict):
        """Add period statistics to a file.
        
        This method accumulates period information for a source file,
        ensuring each file is only counted once per sample.
        
        Arguments:
            file_path_id: ID of the file path
            period: Period object to add
            used_file_dict: Dictionary tracking used files in current sample
        """
        if file_path_id not in used_file_dict:
            used_file_dict[file_path_id] = True
            file_period = self.file_periods.get(file_path_id)
            if file_period is None:
                file_period = self.file_periods[file_path_id] = FilePeriod(file_path_id)
            file_period.add_period(period)

    def _add_line_period(self, file_path_id, line_num, period, function_name_id, start_line, used_line_dict):
        """Add period statistics to a specific line in a file.

        This method accumulates period information for a source line,
        ensuring each line is only counted once per sample.
        
        Arguments:
            file_path_id: ID of the file path
            line_num: Line number
            period: Period object to add
            function_name_id: ID of the function containing this line
            start_line: Starting line number of the function
            used_line_dict: Dictionary tracking used lines in current sample
        """
        key = (file_path_id, line_num)
        if key not in used_line_dict:
            used_line_dict[key] = True
            file_period = self.file_periods.get(file_path_id)
            if file_period:
                file_period.add_line_period(line_num, period, function_name_id, start_line)

    def _add_function_period(self, file_path_id, function_name_id, function_start_line, period, used_function_dict):
        """Add period statistics to a specific function in a file.
        
        This method accumulates period information for a function,
        ensuring each function is only counted once per sample.
        
        Arguments:
            file_path_id: ID of the file path
            function_name_id: ID of the function name
            function_start_line: Starting line number of the function
            period: Period object to add
            used_function_dict: Dictionary tracking used functions in current sample
        """
        key = (file_path_id, function_name_id)
        if key not in used_function_dict:
            used_function_dict[key] = True
            file_period = self.file_periods.get(file_path_id)
            if file_period:
                file_period.add_function_period(function_name_id, function_start_line, period)

    def _write_period(self):
        """Write summary report with period statistics.
        
        This method generates a comprehensive summary report containing:
        1. Total period across all samples
        2. DSO summary (sorted by accumulated period)
        3. File summary (sorted by accumulated period)
        4. Function/line summary for each file
        
        The report is written to 'summary' file in the output directory.
        """
        summary = os.path.join(self.config.get('output_dir', 'annotated_files'), 'summary')
        with open(summary, 'w') as f:
            f.write('total period: %d\n\n' % self.period)
            self._write_dso_summary(f)
            self._write_file_summary(f)

            file_periods = sorted(self.file_periods.values(),
                                  key=lambda x: x.period.acc_period, reverse=True)
            for file_period in file_periods:
                self._write_function_line_summary(f, file_period)

    def _write_dso_summary(self, summary_fh):
        """Write DSO summary section to the report.
        
        This section lists all DSOs sorted by accumulated period,
        showing both total and self periods.
        
        Format:
        === DSO Summary ===
        Total           Self            DSO
        100.00%         50.00%          /system/lib/libapp.so
        ...
        """
        dso_periods = sorted(self.dso_periods.values(),
                              key=lambda x: x.period.acc_period, reverse=True)
        
        col_width = 25 if self.config.get('raw_period', False) else 15
        
        summary_fh.write('=== DSO Summary ===\n')
        summary_fh.write('%-*s %-*s %s\n' % (col_width, 'Total', col_width, 'Self', 'DSO'))
        for dso_period in dso_periods:
            total_str = self._get_period_str(dso_period.period.acc_period)
            self_str = self._get_period_str(dso_period.period.period)
            dso_name = self.string_cache.get_string(dso_period.dso_name_id)
            summary_fh.write('%-*s %-*s %s\n' % (col_width, total_str, col_width, self_str, dso_name))
        summary_fh.write('\n')

    def _write_file_summary(self, summary_fh):
        """Write file summary section to the report.
        
        This section lists all source files sorted by accumulated period,
        showing both total and self periods.
        
        Format:
        === File Summary ===
        Total           Self            Source File
        100.00%         50.00%          /path/to/source.c
        ...
        """
        file_periods = sorted(self.file_periods.values(),
                                key=lambda x: x.period.acc_period, reverse=True)
        
        col_width = 25 if self.config.get('raw_period', False) else 15
        
        summary_fh.write('=== File Summary ===\n')
        summary_fh.write('%-*s %-*s %s\n' % (col_width, 'Total', col_width, 'Self', 'Source File'))
        for file_period in file_periods:
            total_str = self._get_period_str(file_period.period.acc_period)
            self_str = self._get_period_str(file_period.period.period)
            file_path = self.string_cache.get_string(file_period.file_id)
            summary_fh.write('%-*s %-*s %s\n' % (col_width, total_str, col_width, self_str, file_path))
        summary_fh.write('\n')

    def _write_function_line_summary(self, summary_fh, file_period):
        """Write function and line summary for a specific file.
        
        This section lists all functions and lines in a file that have non-zero periods,
        grouped by function with their lines.
        
        Format:
        === Function/Line Summary in /path/to/source.c ===
        Total           Self            Function/Line
        10.00%          10.00%          func_name(StartLine xxx)
        5.00%           5.00%           func_name line xxx
        ...
        
        Arguments:
            summary_fh: File handle to write to
            file_period: FilePeriod object containing line statistics
        """
        col_width = 25 if self.config.get('raw_period', False) else 15
        
        file_path = self.string_cache.get_string(file_period.file_id)
        summary_fh.write('=== Function/Line Summary in %s ===\n' % file_path)
        summary_fh.write('%-*s %-*s  Function/Line\n' % (col_width, 'Total', col_width, 'Self'))
        
        func_list = []
        for func_name_id in file_period.function_dict.keys():
            func_start_line, period = file_period.function_dict[func_name_id]
            func_list.append((func_name_id, func_start_line, period))
        
        func_list.sort(key=lambda x: x[1])
        
        func_lines = {}
        for func_name_id, func_start_line, period in func_list:
            func_lines[func_name_id] = []
        
        for line in sorted(file_period.line_dict.keys()):
            function_name_id, start_line, period = file_period.line_dict[line]
            
            found_func_id = None
            for i in range(len(func_list) - 1, -1, -1):
                func_name_id, func_start_line, _ = func_list[i]
                if line >= func_start_line:
                    found_func_id = func_name_id
                    break
            
            if found_func_id is not None:
                func_lines.get(found_func_id, []).append((line, period))
            else:
                func_lines['_orphan'] = func_lines.get('_orphan', [])
                func_lines['_orphan'].append((line, period))
        
        func_list_sorted = sorted(func_list, key=lambda x: x[2].acc_period, reverse=True)
        
        for func_name_id, func_start_line, period in func_list_sorted:
            total_str = self._get_period_str(period.acc_period)
            self_str = self._get_period_str(period.period)
            func_name = self.string_cache.get_string(func_name_id)
            name = '%s(StartLine %d)' % (func_name, func_start_line)
            summary_fh.write('%-*s %-*s  %s\n' % (col_width, total_str, col_width, self_str, name))
            
            if func_name_id in func_lines:
                for line, line_period in sorted(func_lines[func_name_id], key=lambda x: x[0]):
                    total_str = self._get_period_str(line_period.acc_period)
                    self_str = self._get_period_str(line_period.period)
                    name = '%s line %d' % (func_name, line)
                    summary_fh.write('%-*s %-*s  %s\n' % (col_width, total_str, col_width, self_str, name))
        
        if '_orphan' in func_lines:
            for line, line_period in sorted(func_lines['_orphan'], key=lambda x: x[0]):
                total_str = self._get_period_str(line_period.acc_period)
                self_str = self._get_period_str(line_period.period)
                name = 'line %d' % line
                summary_fh.write('%-*s %-*s  %s\n' % (col_width, total_str, col_width, self_str, name))
        
        summary_fh.write('\n')

    def _get_period_str(self, period):
        """Convert period value to string representation.
        
        This method formats period values with 2 decimal places precision.
        If raw_period is enabled, shows both percentage and raw period.
        
        For Period objects, it returns both accumulated and self periods.
        
        Arguments:
            period: Period value or Period object
            
        Returns:
            Formatted string representation with 2 decimal places
        """
        if isinstance(period, Period):
            return 'Total %s, Self %s' % (
                self._get_period_str(period.acc_period),
                self._get_period_str(period.period))
        if self.period == 0:
            return str(period)
        try:
            period_value = int(period)
        except (ValueError, TypeError):
            period_value = 0
        percentage = 100.0 * period_value / self.period
        if self.config.get('raw_period', False):
            return '%.2f%% (%d)' % (percentage, period_value)
        return '%.2f%%' % percentage

    def _annotate_files(self):
        """Annotate all source files with period information.

        This method copies source files to the output directory and
        adds period comments to each line.

        If source_dirs is not provided, skip file annotation and only
        generate summary report.

        Algorithm:
        1. Check if source_dirs are provided
        2. If not provided, skip annotation
        3. For each file in file_periods:
           - Use source_searcher to find real source file path
           - If real path found, annotatee the file
        4. Comments are added as C-style comments: /* period_info */
        5. Empty lines get no comment
        6. Lines with period info get aligned comments

        Optimization:
        - Uses multithreading for parallel file annotation
        - Shows progress for each file
        """
        source_dirs = self.config.get('source_dirs', [])
        if not source_dirs:
            return

        dest_dir = self.config.get('output_dir', 'annotated_files')

        file_tasks = []
        for file_id, file_period in self.file_periods.items():
            from_path = self.string_cache.get_string(file_id)
            to_path = self._get_output_path_from_source(from_path, dest_dir, source_dirs)

            if not os.path.isfile(from_path):
                logger.warning("  Can't find source file: %s" % from_path)
                continue

            file_tasks.append((from_path, to_path, file_period))

        if not file_tasks:
            return

        logger.info("  Total files: %d" % len(file_tasks))
        logger.info("")

        counter = {'value': 0}
        counter_lock = Lock()
        total_files = len(file_tasks)

        def annotate_file_task(from_path, to_path, file_period):
            with counter_lock:
                counter['value'] += 1
                current = counter['value']
                progress = 100.0 * current / total_files

            self._annotate_file(from_path, to_path, file_period, current, total_files, progress)

        with ThreadPoolExecutor(max_workers=THREAD_POOL_ANNOTATE_WORKERS) as executor:
            futures = []
            for from_path, to_path, file_period in file_tasks:
                future = executor.submit(annotate_file_task, from_path, to_path, file_period)
                futures.append(future)

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.warning("  [ERROR] %s" % e)

        logger.info("")
        logger.info("  Completed: %d files" % total_files)

    def _get_output_path_from_source(self, from_path, dest_dir, source_dirs):
        """Calculate output path for annotated source file.
        
        This method determines the output path by finding the relative path
        from one of the source_dirs and preserving that structure in dest_dir.
        
        Arguments:
            from_path: Absolute path to the source file
            dest_dir: Output directory for annotated files
            source_dirs: List of source directories
            
        Returns:
            Path where the annotated file should be written
        """
        from_path = os.path.normpath(from_path)
        
        for source_dir in source_dirs:
            source_dir = os.path.normpath(source_dir)
            if from_path.startswith(source_dir):
                rel_path = os.path.relpath(from_path, source_dir)
                return os.path.join(dest_dir, rel_path)
        
        basename = os.path.basename(from_path)
        return os.path.join(dest_dir, basename)

    def _annotate_file(self, from_path, to_path, file_period, current=0, total=0, progress=0.0):
        """Annotate a single source file with period information.

        This method reads a source file and writes an annotated version
        with period comments added to each line.

        Comment format:
        - File header: /* [file] Total X%, Self Y% */
        - Function header: /* [func] Total X%, Self Y% */
        - Line comments: /* Total X%, Self Y% */
        - Empty lines: No comment
        - Non-empty lines without period: Aligned empty comment

        Algorithm:
        1. Read all lines from the source file
        2. Create annotation dictionary for lines with period data
        3. Add function annotations at function start lines
        4. Calculate maximum comment width for alignment
        5. Write each line with appropriate comment
        6. Create output directory structure as needed

        Arguments:
            from_path: Path to the source file
            to_path: Path to write the annotated file
            file_period: FilePeriod object containing period statistics
            current: Current file number (for progress display)
            total: Total number of files (for progress display)
            progress: Progress percentage (for progress display)
        """
        if total > 0:
            current_width = len(str(total))
            logger.info("  [%*d/%d, %.1f%%] %s" %
                       (current_width, current, total, progress, from_path))
        else:
            logger.info("  [1/1, 100.0%%] %s" % (from_path))
        
        with open(from_path, 'r', encoding='utf-8', errors='replace') as rf:
            lines = rf.readlines()

        annotations = {}
        for line in file_period.line_dict.keys():
            function_name_id, start_line, period = file_period.line_dict[line]
            annotations[line] = self._get_period_str(period)
        
        for func_name_id in file_period.function_dict.keys():
            func_start_line, period = file_period.function_dict[func_name_id]
            if func_start_line == -1:
                continue
            annotations[func_start_line] = '[func] ' + self._get_period_str(period)
        
        annotations[1] = '[file] ' + self._get_period_str(file_period.period)

        max_annotation_cols = 0
        for key in annotations:
            max_annotation_cols = max(max_annotation_cols, len(annotations[key]))

        empty_annotation = ' ' * (max_annotation_cols + 6)

        dirname = os.path.dirname(to_path)
        if not os.path.isdir(dirname):
            os.makedirs(dirname)
        
        with open(to_path, 'w', encoding='utf-8') as wf:
            for line in range(1, len(lines) + 1):
                annotation = annotations.get(line)
                if annotation is None:
                    if not lines[line-1].strip():
                        annotation = ''
                    else:
                        annotation = empty_annotation
                else:
                    annotation = '/* ' + annotation + (
                        ' ' * (max_annotation_cols - len(annotation))) + ' */'
                wf.write(annotation)
                wf.write(lines[line-1])

    def _generate_disassembly(self, parser):
        """Generate disassembly annotation

        Arguments:
            parser: DumpFileParser object containing parsed samples
        """
        disasm_annotator = DisassemblyAnnotator(
            self.config,
            self.string_cache,
            self.addr2line.file_index,
            self.addr2line
        )

        disasm_annotator.collect_function_ranges(parser)
        disasm_annotator.calculate_addr_periods(parser)
        disasm_annotator.generate_disassembly()


class Disassembly:
    """Disassembly data structure.

    Stores disassembly results for a function, including:
    - lines: List of instructions, each instruction is a (instruction_text, addresses) tuple
    - function_name: Function name
    - start_addr: Function start addresses
    - end_addr: Function end addresses
    """
    def __init__(self):
        self.lines = []
        self.function_name = ''
        self.start_addr = 0
        self.end_addr = 0


class AddrRange:
    """Address range class.

    Used to specify addresses range for disassembly.
    """
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def is_in_range(self, addr):
        """Check if addresses is within range."""
        return self.start <= addr < self.end


class HiperfReadElf:
    """llvm-readelf tool wrapper.

    Provides binary file metadata extraction functions:
    - Get architecture information
    - Get ELF section information
    - Get build ID
    - Verify ELF file
    """

    def __init__(self, ndk_path):
        self.ndk_path = ndk_path
        self.readelf_path = self._find_readelf()

    def get_arch(self, binary_path):
        """Get binary file architecture.

        Returns:
            Architecture string: 'arm64', 'arm', 'x86_64', 'unknown'
        """
        if not self.readelf_path:
            return 'unknown'

        try:
            result = subprocess.run(
                [self.readelf_path, '-h', binary_path],
                capture_output=True, text=True, timeout=READELF_TIMEOUT
            )
            if result.returncode == 0:
                output = result.stdout
                if 'AArch64' in output or 'ARM aarch64' in output:
                    return 'arm64'
                elif 'ARM' in output:
                    return 'arm'
                elif 'x86-64' in output or 'X86-64' in output:
                    return 'x86_64'
                elif 'Intel 8033' in output:
                    return 'x86'
        except Exception as e:
            logger.warning("Failed to get arch for %s: %s" % (binary_path, e))

        return 'unknown'

    def get_build_id(self, binary_path):
        """Get build ID of binary file.

        Returns:
            Build ID string or None
        """
        if not self.readelf_path:
            return None

        try:
            result = subprocess.run(
                [self.readelf_path, '-n', binary_path],
                capture_output=True, text=True, timeout=READELF_TIMEOUT
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Build ID' in line or 'GNU build ID' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            return parts[1].strip()
        except Exception as e:
            logger.warning("Failed to get build ID for %s: %s" % (binary_path, e))

        return None

    def _find_readelf(self):
        """Find llvm-readelf tool.

        Priority:
        1. ndk_path directory
        2. System PATH
        """
        if self.ndk_path:
            exe_path = os.path.join(self.ndk_path, 'llvm-readelf')
            if sys.platform == 'win32' and not exe_path.endswith('.exe'):
                exe_path += '.exe'
            if os.path.isfile(exe_path):
                return exe_path

        for exe in ['llvm-readelf', 'readelf']:
            if self._is_executable_available(exe):
                return exe

        logger.error("Cannot find llvm-readelf. Please install LLVM toolchain or specify --ndk path.")
        return None

    def _is_executable_available(self, exe_name):
        """Check if executable is available."""
        try:
            result = subprocess.run([exe_name, '--version'], capture_output=True, timeout=SYMBOLIZER_TIMEOUT)
            return result.returncode == 0
        except Exception:
            return False


class HiperfBinaryFinder:
    """Binary file finder.

    Uses pre-built file index to quickly find binary files and verify build ID.
    """

    def __init__(self, symbol_dirs, file_index, readelf=None):
        self.symbol_dirs = symbol_dirs if symbol_dirs else []
        self.file_index = file_index if file_index else {}
        self.readelf = readelf

    def find_binary(self, dso_path, expected_build_id=None):
        """Find binary file corresponding to DSO.

        Arguments:
            dso_path: DSO path (may be absolute or relative)
            expected_build_id: Expected build ID (for verification)

        Returns:
            Full path to binary file, None if not found
        """
        dso_name = os.path.basename(dso_path)

        binary_path = self.file_index.get(dso_name)
        if binary_path and os.path.isfile(binary_path):
            if self._validate_build_id(binary_path, expected_build_id):
                return binary_path

        for symbol_dir in self.symbol_dirs:
            candidate = os.path.join(symbol_dir, dso_name)
            if os.path.isfile(candidate):
                if self._validate_build_id(candidate, expected_build_id):
                    return candidate

        return None

    def _validate_build_id(self, binary_path, expected_build_id):
        """Verify build ID of binary file."""
        if not expected_build_id:
            return True

        if not self.readelf:
            return True

        actual_build_id = self.readelf.get_build_id(binary_path)
        if actual_build_id and actual_build_id == expected_build_id:
            return True

        if actual_build_id:
            logger.warning("Build ID mismatch for %s: expected %s, got %s" %
                         (binary_path, expected_build_id, actual_build_id))

        return True


class HiperfObjdump:
    """llvm-objdump tool wrapper.

    Provides disassembly functionality, supports single function and batch disassembly.
    """

    def __init__(self, ndk_path, symbol_dirs, file_index):
        self.ndk_path = ndk_path
        self.symbol_dirs = symbol_dirs if symbol_dirs else []
        self.file_index = file_index if file_index else {}
        self.objdump_path = self._find_objdump()
        self.readelf = HiperfReadElf(ndk_path)
        self.objdump_cache = {}
        self.binary_finder = HiperfBinaryFinder(symbol_dirs, file_index, self.readelf)

    def get_dso_info(self, dso_path, expected_build_id):
        """Get DSO information.

        Returns:
            (binary_path, arch) tuple, (None, None) if not found
        """
        binary_path = self.binary_finder.find_binary(dso_path, expected_build_id)
        if not binary_path:
            logger.warning("Binary not found for %s" % dso_path)
            return (None, None)

        arch = self.readelf.get_arch(binary_path)
        if arch == 'unknown':
            logger.warning("Unknown architecture for %s" % binary_path)
            return (None, None)

        return (binary_path, arch)

    def disassemble_functions(self, dso_info, addr_ranges):
        """Batch disassemble multiple functions (optimized version).

        Arguments:
            dso_info: (binary_path, arch) tuple
            addr_ranges: AddrRange object list, sorted by start address

        Returns:
            Disassembly object list
        """
        if not addr_ranges:
            return []

        if not self.objdump_path:
            logger.warning("llvm-objdump not available")
            return []

        real_path, arch = dso_info
        objdump_path = self.objdump_cache.get(arch)
        if not objdump_path:
            objdump_path = self.objdump_path
            self.objdump_cache[arch] = objdump_path

        context_bytes = DISASSEMBLY_CONTEXT_BYTES
        start_addr = addr_ranges[0].start - context_bytes
        stop_addr = max(addr_range.end for addr_range in addr_ranges) + context_bytes

        args = [
            objdump_path,
            '-dlC',
            '--no-show-raw-insn',
            '--start-address=0x%x' % start_addr,
            '--stop-address=0x%x' % stop_addr,
            real_path
        ]

        if arch == 'arm' and 'llvm-objdump' in objdump_path:
            args.append('--print-imm-hex')

        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, text=True)
            result = self._parse_disassembly_for_functions(proc.stdout, addr_ranges)
            proc.wait()
            return result
        except Exception as e:
            logger.warning("Failed to disassemble functions: %s" % e)

        return []

    def _find_objdump(self):
        """Find llvm-objdump tool.

        Priority:
        1. ndk_path directory
        2. System PATH
        """
        if self.ndk_path:
            exe_path = os.path.join(self.ndk_path, 'llvm-objdump')
            if sys.platform == 'win32' and not exe_path.endswith('.exe'):
                exe_path += '.exe'
            if os.path.isfile(exe_path):
                return exe_path

        for exe in ['llvm-objdump', 'objdump']:
            if self._is_executable_available(exe):
                return exe

        logger.error("Cannot find llvm-objdump. Please install LLVM toolchain or specify --ndk path.")
        return None

    def _is_executable_available(self, exe_name):
        """Check if executable is available."""
        try:
            result = subprocess.run([exe_name, '--version'], capture_output=True, timeout=SYMBOLIZER_TIMEOUT)
            return result.returncode == 0
        except Exception:
            return False

    def _parse_disassembly_output(self, output, addr_range):
        """Parse disassembly output.

        Arguments:
            output: llvm-objdump stdout
            addr_range: Address range

        Returns:
            Disassembly object
        """
        disassembly = Disassembly()
        disassembly.start_addr = addr_range.start
        disassembly.end_addr = addr_range.end

        for line in output.split('\n'):
            line = line.rstrip()
            addr = self._get_addr_from_disassembly_line(line)
            disassembly.lines.append((line, addr))

        return disassembly

    def _parse_disassembly_for_functions(self, fh, addr_ranges):
        """Parse batch disassembly output and split by function.

        Arguments:
            fh: File handle
            addr_ranges: AddrRange object list, sorted by start address

        Returns:
            Disassembly object list
        """
        result = [Disassembly() for _ in addr_ranges]

        for i, addr_range in enumerate(addr_ranges):
            result[i].start_addr = addr_range.start
            result[i].end_addr = addr_range.end

        all_lines = []
        while True:
            line = fh.readline()
            if not line:
                break
            line = line.rstrip()
            addr = self._get_addr_from_disassembly_line(line)
            all_lines.append((line, addr))

        for i, addr_range in enumerate(addr_ranges):
            for line, addr in all_lines:
                if addr == 0:
                    continue
                if addr_range.is_in_range(addr):
                    result[i].lines.append((line, addr))

        for disassembly in result:
            disassembly.lines.sort(key=lambda x: x[1] if x[1] > 0 else 0)

        return result

    def _get_addr_from_disassembly_line(self, line):
        """Extract addresses from disassembly line.

        Arguments:
            line: Disassembly output line

        Returns:
            Address value (integer), 0 if extraction fails
        """
        items = line.strip().split()
        if not items:
            return 0

        s = items[0]
        if s.endswith(':'):
            s = s[:-1]

        try:
            return int(s, 16)
        except ValueError:
            return 0


class DisassemblyAnnotator:
    """Disassembly annotation generator.

    This class orchestrates the entire disassembly annotation process:
    1. Collect function addresses ranges from samples
    2. Group by DSO
    3. Disassemble functions
    4. Associate performance data with instructions
    5. Generate annotated disassembly files
    """

    def __init__(self, config, string_cache, file_index, addr2line):
        self.config = config
        self.string_cache = string_cache
        self.file_index = file_index
        self.addr2line = addr2line

        self.objdump = HiperfObjdump(
            config.get('ndk_path'),
            config.get('symdir', []),
            file_index
        )

        self.function_ranges = {}
        self.addr_periods = {}
        self.disassembly_cache = {}
        self.total_period = 0
        self.dso_filter = set(config.get('dso_filters', []))

    def collect_function_ranges(self, parser):
        """Collect function address ranges from parsed samples.

        Arguments:
            parser: DumpFileParser object containing parsed samples
        """
        logger.info("  Collecting function ranges...")

        for sample in parser.samples:
            if not sample.callchain:
                continue

            for symbol in sample.callchain:
                if not self._filter_symbol(symbol):
                    continue

                dso_name = self.string_cache.get_string(symbol.dso_name_id)
                addr = symbol.symbol_addr

                sources = self.addr2line.get_sources(dso_name, addr)
                if sources:
                    func = sources[-1][2] if sources[-1][2] else ''
                else:
                    func = self.string_cache.get_string(symbol.symbol_name_id)

                key = (dso_name, func)
                if key not in self.function_ranges:
                    self.function_ranges[key] = {
                        'start': symbol.symbol_addr,
                        'end': symbol.symbol_addr + 1,
                        'build_id': symbol.build_id
                    }
                else:
                    func_info = self.function_ranges[key]
                    func_info['start'] = min(func_info['start'], symbol.symbol_addr)
                    func_info['end'] = max(func_info['end'], symbol.symbol_addr)

        logger.info("  Function ranges: %d" % len(self.function_ranges))

    def calculate_addr_periods(self, parser):
        """Calculate period statistics for each address

        Arguments:
            parser: DumpFileParser object containing parsed samples
        """
        logger.info("  Calculating address periods...")

        for sample in parser.samples:
            if not sample.callchain:
                continue

            sample_used = False

            for j, symbol in enumerate(sample.callchain):
                if not self._filter_symbol(symbol):
                    continue

                if not sample_used:
                    self.total_period += sample.period
                    sample_used = True

                dso_name = self.string_cache.get_string(symbol.dso_name_id)
                addr = symbol.symbol_addr

                key = (dso_name, addr)
                if key not in self.addr_periods:
                    self.addr_periods[key] = 0

                self.addr_periods[key] += sample.period

        logger.info("  Addresses: %d" % len(self.addr_periods))
        logger.info("  Total period: %d" % self.total_period)
        logger.info("")

    def generate_disassembly(self):
        """Generate annotated disassembly for all functions
 
        Workflow:
        1. Group functions by DSO
        2. For each DSO:
            a. Get DSO information (path, architecture)
            b. Prepare addresses ranges
            c. Batch disassemble functions
            d. Annotate with period data
        3. Write annotated disassembly files
        """
        dso_groups = {}
        for (dso_name, func_name), func_info in self.function_ranges.items():
            if dso_name not in dso_groups:
                dso_groups[dso_name] = {
                    'functions': [],
                    'build_id': func_info['build_id']
                }
            dso_groups[dso_name]['functions'].append((func_name, func_info))

        output_dir = self.config.get('disassembly_output_dir', 'annotated_disassembly')
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)

        counter = {'value': 0}
        counter_lock = Lock()
        total_dso = len(dso_groups)

        def process_dso(dso_name, dso_info):
            with counter_lock:
                counter['value'] += 1
                current = counter['value']

            dso_basename = os.path.basename(dso_name)
            current_width = len(str(total_dso))
            progress = 100.0 * current / total_dso
            func_count = len(dso_info['functions'])
            start_time = time.time()

            build_id = dso_info['build_id']
        
            dso_size_threshold = self.config.get('dso_size_threshold', DEFAULT_DSO_SIZE_THRESHOLD)
            binary_path = self.file_index.get(dso_basename)
            if binary_path and os.path.isfile(binary_path):
                file_size = os.path.getsize(binary_path)
                if file_size > dso_size_threshold:
                    logger.info("[%*d/%d, %.1f%%] Skipping large DSO: %s (size: %d bytes > threshold: %d bytes)" %
                               (current_width, current, total_dso, progress, dso_basename, file_size, dso_size_threshold))
                    return
            else:
                logger.warning("[%*d/%d, %.1f%%] Binary not found for DSO: %s, skipping" %
                              (current_width, current, total_dso, progress, dso_basename))
                return

            dso_obj_info = self.objdump.get_dso_info(binary_path, build_id)
            if dso_obj_info[0] is None:
                logger.warning("[%*d/%d, %.1f%%] Cannot get DSO info for %s" %
                             (current_width, current, total_dso, progress, dso_name))
                return

            functions = dso_info['functions']
            addr_ranges = []
            for func_name, func_info in functions:
                addr_range = AddrRange(
                    func_info['start'],
                    func_info['end']
                )
                addr_ranges.append((func_name, addr_range))

            sorted_ranges = sorted(addr_ranges, key=lambda x: x[1].start)
            range_objects = [r[1] for r in sorted_ranges]

            disassemblies = self.objdump.disassemble_functions(
                dso_obj_info,
                range_objects
            )

            if not disassemblies:
                logger.warning("[%*d/%d, %.1f%%] No disassembly generated for %s" %
                             (current_width, current, total_dso, progress, dso_name))
                return

            annotated = {}
            for i, (func_name, addr_range) in enumerate(sorted_ranges):
                if i < len(disassemblies):
                    disasm = disassemblies[i]
                    disasm.function_name = func_name
                    annotated[func_name] = self._annotate_disassembly(
                        dso_name,
                        disasm
                    )

            self._write_disassembly_files(output_dir, dso_basename, annotated)

            elapsed = time.time() - start_time
            logger.info("  [%*d/%d, %.1f%%] Completed %s (%.2fs, %d functions)" %
                       (current_width, current, total_dso, progress, dso_basename, elapsed, func_count))

        with ThreadPoolExecutor(max_workers=THREAD_POOL_ANNOTATE_WORKERS) as executor:
            futures = []
            for dso_name, dso_info in dso_groups.items():
                future = executor.submit(process_dso, dso_name, dso_info)
                futures.append(future)

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.warning("Error processing DSO: %s" % e)

    def _annotate_disassembly(self, dso_path, disassembly):
        """Annotate disassembly with period information

        Arguments:
            dso_path: DSO identifier
            disassembly: Disassembly object

        Returns:
            Annotated disassembly text
        """
        lines = []

        header = '/* Function: %s */' % disassembly.function_name
        lines.append(header)

        for instruction, addr in disassembly.lines:
            key = (dso_path, addr)
            period = self.addr_periods.get(key, 0)

            if period > 0:
                total_percent = 100.0 * period / self.total_period
                if self.config.get('raw_period', False):
                    period_str = '/* %.2f%% (%d) */' % (total_percent, period)
                else:
                    period_str = '/* %.2f%% */' % total_percent
            else:
                period_str = ''

            if period_str:
                lines.append('%-50s %s' % (period_str, instruction))
            else:
                lines.append('%-50s %s' % ('', instruction))

        return '\n'.join(lines)

    def _write_disassembly_files(self, output_dir, dso_name, annotated_disassembly):
        """Write annotated disassembly files

        Arguments:
            output_dir: Output directory
            dso_name: DSO name
            annotated_disassembly: Mapping from function name to annotated text
        """
        if not annotated_disassembly:
            return

        dso_dir = os.path.join(output_dir, dso_name)
        if not os.path.exists(dso_dir):
            os.makedirs(dso_dir)

        for i, (func_name, annotated_text) in enumerate(annotated_disassembly.items(), 1):
            safe_func_name = ''.join(c if c.isalnum() or c in ['_', '-', '.'] else '_' for c in func_name)
            safe_func_name = re.sub(r'_+', '_', safe_func_name)
            safe_func_name = safe_func_name[:SAFE_FUNC_NAME_MAX_LENGTH]
            output_file = os.path.join(dso_dir, '%s.asm' % safe_func_name)

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(annotated_text)

    def _filter_symbol(self, symbol):
        """Filter symbols based on DSO filter

        Arguments:
            symbol: Symbol object

        Returns:
            True if symbol should be included, False otherwise
        """
        if not self.dso_filter:
            return True
        dso_name = self.string_cache.get_string(symbol.dso_name_id)
        dso_basename = os.path.basename(dso_name)
        return dso_basename in self.dso_filter


def detect_file_type(filename):
    """Detect the type of profiling file.
    
    This method determines whether a file is:
    - perf.data.dump: Text-based dump format
    - perf.data: Binary perf data format
    - unknown: Unsupported format
    
    Detection algorithm:
    1. Check file extension (.dump)
    2. Read magic number from binary file (PERFILE2)
    3. Return appropriate file type
    
    Arguments:
        filename: Path to the file
        
    Returns:
        File type string ('perf.data.dump', 'perf.data', or 'unknown')
    """
    if filename.endswith('.dump'):
        return 'perf.data.dump'
    
    try:
        with open(filename, 'rb') as f:
            magic = f.read(8)
            if magic == b'PERFILE2':
                return 'perf.data'
    except Exception:
        pass
    
    return 'unknown'


def convert_to_dump_if_needed(input_file):
    """Convert perf.data to dump format if necessary.
    
    This method ensures the input file is in dump format:
    1. If already a dump file, return as-is
    2. If a perf.data file, convert using hiperf_utils
    3. Otherwise, raise an error
    
    Conversion algorithm:
    1. Detect file type
    2. If perf.data, call hiperf_utils.Dump() with appropriate arguments
    3. The Dump command creates a .dump file alongside the input
    4. Return the path to the dump file
    
    Arguments:
        input_file: Path to the input file
        
    Returns:
        Path to the dump file (either original or converted)
        
    Raises:
        Exception: If file type is unknown or conversion fails
    """
    file_type = detect_file_type(input_file)
    
    if file_type == 'perf.data.dump':
        logger.info("  Input file is already a dump file: %s" % input_file)
        return input_file
    
    if file_type == 'perf.data':
        dump_file = input_file + '.dump'
        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Convert perf.data to dump file")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("  Input: %s" % input_file)
        logger.info("  Output: %s" % dump_file)
        
        start_time = time.time()
        lib = hiperf_utils.get_lib()
        result = lib.Dump(f'-i {input_file} -o {dump_file}'.encode('utf-8'))
        elapsed = time.time() - start_time
        
        if result == 0:
            logger.info("  Time: %.2fs" % elapsed)
            return dump_file
        else:
            raise Exception("Failed to convert %s to dump" % input_file)
    
    raise Exception("Unknown file type: %s" % input_file)


def parse_args():
    """Parse command line arguments.
    
    This method defines and parses all command line options for the
    annotation tool.
    
    Arguments:
        -i, --input: Input file (perf.data or perf.data.dump) [required]
        -s, --source_dirs: Directories to find source files
        --symdir: Directory to find symbol files (default: ./binary_cache)
        --ndk: Path to NDK (for llvm-symbolizer)
        --raw-period: Show raw period instead of percentage
        --summary-width: Max width of summary file (default: 80)
        --dso: Only annotate samples in selected DSOs
        -o, --output: Output directory for annotated files (default: annotated_files)
        
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='Annotate source files based on profiling data.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-i', '--input', required=True,
                        help='Input file (perf.data or perf.data.dump)')
    parser.add_argument('-s', '--source_dirs', nargs='+',
                        help='Directories to find source files')
    parser.add_argument('--sym_dir', nargs='+', default=['./binary_cache'],
                        help='Directories to find symbol files (can specify multiple)')
    parser.add_argument('--ndk_path',
                        help='Path to NDK (for llvm-symbolizer)')
    parser.add_argument('--raw_period', action='store_true',
                        help='Show raw period instead of percentage')
    parser.add_argument('--summary_width', type=int, default=80,
                        help='Max width of summary file (default: 80)')
    parser.add_argument('--dso', nargs='+',
                        help='Only annotate samples in selected DSOs')
    parser.add_argument('-o', '--output', default='annotated_files',
                        help='Output directory for annotated files (default: annotated_files)')
    parser.add_argument('--disassembly_output_dir', default='annotated_disassembly',
                        help='Output directory for disassembly (default: annotated_disassembly)')
    parser.add_argument('--add_disassembly', action='store_true',
                        help='Generate disassembly annotation')
    parser.add_argument('--dso_size_threshold', type=int, default=DEFAULT_DSO_SIZE_THRESHOLD,
                        help='DSO size threshold in bytes (default: 1G, skip addr2line/objdump for DSOs larger than this)')

    return parser.parse_args()


def main():
    """Main entry point for HiPerf annotation tool.
    
    This method orchestrates the entire annotation process:
    1. Parse command line arguments
    2. Convert input file to dump format if needed
    3. Create configuration dictionary
    4. Initialize and run the SourceFileAnnotator
    5. Handle errors and provide user feedback
    
    Error handling:
    - All exceptions are caught and logged
    - Stack trace is printed for debugging
    - Process exits with status code 1 on error
    """
    args = parse_args()
    
    logger.info("=" * LOG_SEPARATOR_LENGTH)
    logger.info("HiPerf Annotate Tool")
    logger.info("=" * LOG_SEPARATOR_LENGTH)
    logger.info("  Input file: %s" % args.input)
    
    try:
        dump_file = convert_to_dump_if_needed(args.input)

        parse_start_time = time.time()
        parser = DumpFileParser(dump_file)
        parser.parse()
        parse_elapsed = time.time() - parse_start_time
        logger.info("  Time: %.2fs" % parse_elapsed)

        config = {
            'source_dirs': args.source_dirs,
            'symdir': args.sym_dir,
            'ndk_path': args.ndk_path,
            'raw_period': args.raw_period,
            'summary_width': args.summary_width,
            'dso_filters': args.dso or [],
            'output_dir': args.output,
            'disassembly_output_dir': args.disassembly_output_dir,
            'dso_size_threshold': args.dso_size_threshold
        }

        annotator = SourceFileAnnotator(config, parser.string_cache)
        annotator.annotate(parser, enable_disassembly=args.add_disassembly)

        logger.info("")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Annotate completed successfully")
        logger.info("=" * LOG_SEPARATOR_LENGTH)
        logger.info("Output directories:")
        logger.info("  Annotated files: %s" % args.output)
        
        if args.add_disassembly:
            logger.info("  Disassembly: %s" % args.disassembly_output_dir)
    except Exception as e:
        logger.error("Annotate failed: %s" % e)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
