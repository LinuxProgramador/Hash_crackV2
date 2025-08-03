#!/usr/bin/env python3

import sys
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from itertools import islice

HOME = Path.home()
TEMP_FILE = HOME / "Hash_crackV2" / "temp.txt"
WORDLIST_FILE = HOME / "Hash_crackV2" / "wordlist.txt"
BLOCK_LINES = 10000  # Lines per reading block
NUM_THREADS = 4      # You can adjust depending on CPU


def pairwise(lines):
    return zip(lines[:-1], lines[1:])

def process_chunk(chunk_lines):
    buffer = []
    for prev, curr in pairwise(chunk_lines):
        prev, curr = prev.strip(), curr.strip()
        if prev and curr:
            buffer.append(f"{curr}{prev}\n")
            buffer.append(f"{prev}{curr}\n")
    return buffer

def generate_combinations(encoder):
    print("This will take time...")

    try:
        with open(WORDLIST_FILE, 'r', encoding=encoder) as infile, \
             open(TEMP_FILE, 'w', encoding=encoder) as outfile:

            prev_tail = []
            while True:
                # Read a block of lines
                block = list(islice(infile, BLOCK_LINES))
                block = [line for line in block if line.strip()]
                if not block:
                    break

                # If there's leftover from previous block, prepend it
                if prev_tail:
                    block.insert(0, prev_tail[0])

                prev_tail = [block[-1]] if block else []

                # Split block into NUM_THREADS chunks (with overlap)
                size = len(block)
                step = max(2, size // NUM_THREADS)
                chunks = []

                for i in range(0, size - 1, step):
                    subblock = block[i:i + step + 1]  # +1 to preserve overlap
                    chunks.append(subblock)

                # Process chunks in threads
                combined = []
                with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
                    futures = [executor.submit(process_chunk, chunk) for chunk in chunks]
                    for future in futures:
                        combined.extend(future.result())

                # Write to file
                outfile.writelines(combined)

        os.replace(TEMP_FILE, WORDLIST_FILE)
        print('Done! Now run the main module again: "Hasher.py"')


    except KeyboardInterrupt:
        print()
        sys.exit(1)

    except Exception as error:
        print(f"[ERROR]: An unexpected error occurred: {error}")
        sys.exit(1)
