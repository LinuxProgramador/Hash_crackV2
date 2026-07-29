#!/usr/bin/env python3

import os
import sys
import subprocess, signal, shutil
from multiprocessing import Pool, cpu_count

def try_passwords(args):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    zip_file, file_7z, passwords = args

    for pwd in passwords:

        cmd = [file_7z, 't', zip_file, f'-p{pwd}']

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
                     
                extract_cmd = [
                    file_7z,
                    'x',
                    zip_file,
                    f'-p{pwd}',
                    '-oDecryptedTablets',
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

        except Exception as e:
            print(f"[ERROR] {e}")
            continue

    return None


def crack_zip(zip_file, wordlist_file):
    try:
      if shutil.which("7zz"):
          file_7z = "7zz"
      else:
          file_7z = "7z"
      read_block_size = 8 * 1024 * 1024
      encoder = "utf-8"
      process_count = max(1, cpu_count() - 1)
      result = None
      with Pool(processes=process_count) as pool:
        with open(wordlist_file, 'r', encoding=encoder, errors='ignore') as f:
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
                    (zip_file, file_7z, chunk)
                     for chunk in chunks[:actual_processes]
                ]

                for result in pool.imap_unordered(try_passwords, tasks):
                   if result:
                      pool.terminate()
                      return

            if last_line:
               result = try_passwords((zip_file, file_7z, [last_line]))
               if result:
                  return
      if not result:
            print("[FINISH]>> PASSWORD NOT FOUND")

    except KeyboardInterrupt:
        print()
        sys.exit(1)

    except FileNotFoundError:
        print(f"[ERROR]: Wordlist file not found: {wordlist_file}")
        sys.exit(1)

    except Exception as e:
        print(f"[ERROR]: {e}")
        sys.exit(1)


if __name__ == "__main__":
  try:
    zip_file = input("Enter the absolute path of the ZIP file you want to crack: ").strip()
    wordlist_file = os.path.expanduser('~/Hash_crackV2/wordlist.txt')
    crack_zip(zip_file, wordlist_file)
  except KeyboardInterrupt:
      print()
      sys.exit(1)
