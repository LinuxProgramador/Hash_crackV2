#!/usr/bin/env python3

import os
import sys
import time, signal
import subprocess
from multiprocessing import Pool


def try_passwords(args):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    archive_file, passwords = args

    for pwd in passwords:
        pwd = pwd.strip()

        cmd = ['7z', 't', archive_file, f'-p{pwd}']

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            output = result.stdout + result.stderr

            if "Everything is Ok" in output:

                print("\n" + "=" * 50)
                print("[ PASSWORD FOUND ]".center(50))
                print("=" * 50)
                print(f">>> Recovered Password: {pwd}".center(50))
                print("=" * 50 + "\n")

                extract_cmd = [
                    '7z',
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

                return pwd, True

            elif (
                "Wrong password" in output
                or "Can not open file as archive" in output
            ):
                continue

        except subprocess.TimeoutExpired:
            continue

        except KeyboardInterrupt:
            return None

        except Exception as e:
            print(f"[ERROR] {e}")
            continue

    return None


def crack_7z(archive_file, wordlist_file):
    try:
      read_block_size = 8 * 1024 * 1024
      encoder = "utf-8"
      process_count = 4
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

                if not lines:
                    continue

                chunk_size = (len(lines) + process_count - 1) // process_count
                chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
                actual_processes = min(process_count, len(chunks))

                tasks = [
                  (
                     archive_file,
                     chunk
                  )
                     for chunk in chunks[:actual_processes]
                ]

                for result in pool.imap_unordered(try_passwords, tasks):
                    if result:
                       pool.terminate()
                       return

            if last_line:
               result = try_passwords((archive_file, [last_line]))
               if result:
                   return
      if not result:
            print("[FINISH]>> PASSWORD NOT FOUND")

    except FileNotFoundError:
        print(f"[ERROR]: Wordlist file not found: {wordlist_file}")
        sys.exit(1)

    except KeyboardInterrupt:
        print()
        sys.exit(1)

    except Exception as e:
        print(f"[ERROR]: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        archive_file = input("Enter the absolute path of the 7Z file you want to crack: ").strip()
        wordlist_file = os.path.expanduser('~/Hash_crackV2/wordlist.txt')
        crack_7z(archive_file, wordlist_file)
    except KeyboardInterrupt:
        print()
        sys.exit(1)
