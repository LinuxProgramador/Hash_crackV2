#!/usr/bin/env python3

import sys
from multiprocessing import cpu_count

def get_cpu_allocation(hash_type, cpu_num, use_cpu_num ):
  try:

    is_limited = hash_type in {"argon2id", "scrypt" ,"yescrypt"}
    if is_limited:
        if use_cpu_num and 1 <= cpu_num <= cpu_count():
           process_count = cpu_num
        elif use_cpu_num:
           process_count = cpu_count()
        else:
           process_count = 1

    elif cpu_num and 1 <= cpu_num <= cpu_count():
        process_count = cpu_num

    else:
        process_count = cpu_count()

    return process_count

  except Exception as error:
    print(f"[ERROR]: {error}")
    sys.exit(1)
