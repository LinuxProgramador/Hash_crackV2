#!/usr/bin/env python3

import os
import sys
import subprocess, signal
from multiprocessing import Pool, cpu_count

def init_worker():
   signal.signal(signal.SIGINT, signal.SIG_IGN)
   signal.signal(signal.SIGTSTP, signal.SIG_IGN)


def try_passwords(args):
    rar_file, passwords = args

    for pwd in passwords:
        cmd = ['unrar', 't', f'-p{pwd}', "-idq", rar_file]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print("\n" + "=" * 50)
                print("=" * 50)
                print("[ PASSWORD FOUND ]".center(50))
                print("=" * 50)
                print(f">>> Recovered Password: {pwd}".center(50))
                print("=" * 50 + "\n")
                if pwd != pwd.strip():
                   print("[WARNING:] The password contains leading or trailing whitespace")
                return True

        except subprocess.TimeoutExpired:
            continue

        except Exception as e_:
            print(f"[ERROR] {e_}")
            return True # returns a false positive to stop the code due to the given exception

    return None


def main(rar_file, wordlist_file):
    try:
      read_block_size = 8 * 1024 * 1024
      process_count = max(1, cpu_count() - 1)
      result = None
      with Pool(processes=process_count, initializer=init_worker) as pool:
        with open(wordlist_file, 'r', encoding="utf-8", errors='ignore') as f:
            last_line = ""
            while True:
                chunk = f.read(read_block_size)
                if not chunk:
                    break

                buffer = last_line + chunk
                lines = buffer.splitlines()

                if chunk and not chunk.endswith('\n') and lines:
                    last_line = lines.pop()
                else:
                    last_line = ""

                total_words = len(lines)
                if total_words == 0:
                    continue

                chunk_size = (total_words + process_count - 1) // process_count
                chunks = [lines[i:i + chunk_size] for i in range(0, total_words, chunk_size)]
                actual_processes = min(process_count, len(chunks))

                tasks = [
                  (rar_file, chunk)
                  for chunk in chunks[:actual_processes]
                ]

                for result in pool.imap_unordered(try_passwords, tasks):
                    if result:
                       pool.terminate()
                       return

            if last_line:
               result = try_passwords((rar_file, [last_line]))
               if result:
                  return
                  
      print("[FINISH]>> PASSWORD NOT FOUND")

    except KeyboardInterrupt:
        print()
        sys.exit(0)

    except FileNotFoundError as f:
        print(f"[ERROR]: file not found: {f}")
        sys.exit(1)

    except Exception as e:
        print(f"[ERROR]: {e}")
        sys.exit(1)


if __name__ == "__main__":
  try:
    rar_file = input("Enter the absolute path of the RAR file you want to crack: ").strip()
    wordlist_file = os.path.expanduser('~/Hash_crackV2/wordlist.txt')
    main(rar_file, wordlist_file)

  except KeyboardInterrupt:
      print()
      sys.exit(0)
