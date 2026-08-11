#!/usr/bin/env python3

import os
import sys
import signal
import subprocess, shutil
from multiprocessing import Pool, cpu_count

def init_worker():
   signal.signal(signal.SIGINT, signal.SIG_IGN)
   signal.signal(signal.SIGTSTP, signal.SIG_IGN)


def try_passwords(args):
    archive_file, sevenzip_cmd, passwords = args
    for pwd in passwords:
        cmd = [sevenzip_cmd, 't', archive_file, f'-p{pwd}']
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print("\n" + "=" * 50)
                print("[ PASSWORD FOUND ]".center(50))
                print("=" * 50)
                print(f">>> Recovered Password: {pwd}".center(50))
                print("=" * 50 + "\n")
                if pwd != pwd.strip():
                   print("[WARNING]: The password contains leading or trailing whitespace")
                    
                extract_cmd = [
                    sevenzip_cmd,
                    'x',
                    archive_file,
                    f'-p{pwd}',
                    '-oDecryptedFiles',
                    '-aoa'
                ]

                try:
                    subprocess.run(
                        extract_cmd,
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                except subprocess.CalledProcessError:
                    pass

                return True

        except subprocess.TimeoutExpired:
            continue

        except Exception as e_:
            print(f"[ERROR] {e_}")
            return True # returns a false positive to stop the code due to the given exception

    return None


def main(archive_file, wordlist_file):
    try:
      if shutil.which("7zz"):
          sevenzip_cmd = "7zz"
      else:
          sevenzip_cmd = "7z"
         
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

                if not lines:
                    continue

                chunk_size = (len(lines) + process_count - 1) // process_count
                chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
                actual_processes = min(process_count, len(chunks))

                tasks = [
                  (
                     archive_file,
                     sevenzip_cmd,
                     chunk
                  )
                     for chunk in chunks[:actual_processes]
                ]

                for result in pool.imap_unordered(try_passwords, tasks):
                    if result:
                       pool.terminate()
                       return

            if last_line:
               result = try_passwords((archive_file, sevenzip_cmd, [last_line]))
               if result:
                   return
      
      print("[FINISH]>> PASSWORD NOT FOUND")

    except FileNotFoundError as f:
        print(f"[ERROR]: file not found: {f}")
        sys.exit(1)

    except KeyboardInterrupt:
        print()
        sys.exit(0)

    except Exception as e:
        print(f"[ERROR]: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        archive_file = input("Enter the absolute path of the 7Z file you want to crack: ").strip()
        wordlist_file = os.path.expanduser('~/Hash_crackV2/wordlist.txt')
        main(archive_file, wordlist_file)
       
    except KeyboardInterrupt:
        print()
        sys.exit(0)
