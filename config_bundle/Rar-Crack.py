#!/usr/bin/env python3

import os
import sys
import time
import subprocess
from multiprocessing import Process, Queue, Event


def try_passwords(rar_file, passwords, found, queue):
    for pwd in passwords:
        if found.is_set():
            return
        pwd = pwd.strip()
        cmd = ['7z', 't', rar_file, f'-p{pwd}']

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr

            if "Everything is Ok" in output:
                print("\n" + "=" * 50)
                print("=" * 50)
                print("[ PASSWORD FOUND ]".center(50))
                print("=" * 50)
                print(f">>> Recovered Password: {pwd}".center(50))
                print("=" * 50 + "\n")
                queue.put(pwd)
                found.set()
                return

            elif "Wrong password" in output:
                continue

        except subprocess.TimeoutExpired:
            continue

        except KeyboardInterrupt:
            print()
            found.set()
            return

        except Exception as e:
            print(f"[ERROR] {e}")
            continue


def crack_rar(rar_file, wordlist_file):
    try:
        read_block_size = 1024 * 1024
        encoder = "utf-8"
        found = Event()
        queue = Queue()
        process_count = 4

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

                processes = [
                    Process(target=try_passwords, args=(
                        rar_file, chunk, found, queue
                    )) for chunk in chunks[:actual_processes]
                ]

                try:
                    for p in processes:
                        p.start()

                    while any(p.is_alive() for p in processes):
                        if found.is_set():
                            for p in processes:
                                p.terminate()
                            break
                        time.sleep(0.05)

                    for p in processes:
                        p.join()

                except KeyboardInterrupt:
                    print()
                    for p in processes:
                        p.terminate()
                    break

                except Exception as e:
                    print(f"[ERROR]: {e}")

                finally:
                    for p in processes:
                        if p.is_alive():
                            p.terminate()
                    for p in processes:
                        p.join()

            if last_line and not found.is_set():
                try_passwords(rar_file, [last_line], found, queue)


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
    rar_file = input("Enter the absolute path of the RAR file you want to crack: ").strip()
    wordlist_file = os.path.expanduser('~/Hash_crackV2/wordlist.txt')
    crack_rar(rar_file, wordlist_file)
