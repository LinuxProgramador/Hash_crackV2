#!/usr/bin/env python3

import sys
from multiprocessing import cpu_count

def get_cpu_allocation(hash_type, cpu_num):
  try:

    is_limited = hash_type in ["argon2id", "scrypt"]
    if is_limited:
        process_count = 1

    elif cpu_num and cpu_num <= cpu_count():
        process_count = cpu_num

    else:
        process_count = cpu_count()

    return process_count

  except Exception as error:
    print(f"[ERROR]: {error}")
    sys.exit(1)
