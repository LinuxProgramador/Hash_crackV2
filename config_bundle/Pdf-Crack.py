#!/usr/bin/env python3

import pikepdf
import sys
import os
import time
from pikepdf import PasswordError
from multiprocessing import Process, Queue, Event


def try_passwords(pdf_file, passwords, found, queue):
    for password in passwords:
        if found.is_set():
            return
        pwd = password.strip()
        try:
            with pikepdf.open(pdf_file, password=pwd) as pdf:
                pdf.save("pdf_decryption.pdf")
                print("\n" + "=" * 50)
                print("=" * 50)
                print("[ PASSWORD FOUND ]".center(50))
                print("=" * 50)
                print(f">>> Recovered Password: {pwd}".center(50))
                print("=" * 50 + "\n")
                queue.put(pwd)
                found.set()
                return

        except PasswordError:
            pass

        except Exception as error:
            print(f"[ERROR]: {error}")
            found.set()
            return


def crack_pdf(pdf_file, wordlist_file):
    try:
        read_block_size = 1024 * 1024
        encoder = "utf-8"

        found = Event()
        queue = Queue()
        process_count = 4

        with open(wordlist_file, 'r', encoding=encoder, errors='ignore') as keywords_read:
            last_line = ""
            while True:
                chunk = keywords_read.read(read_block_size)
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
                        pdf_file, chunk, found, queue
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

                except Exception as error:
                    print(f"[ERROR]: {error}")

                finally:
                    for p in processes:
                        if p.is_alive():
                            p.terminate()
                    for p in processes:
                        p.join()

            if last_line and not found.is_set():
                try_passwords(pdf_file, [last_line], found, queue)


    except KeyboardInterrupt:
        print()
        sys.exit(1)

    except FileNotFoundError:
        print(f"[ERROR]: File not found {wordlist_file}")
        sys.exit(1)

    except Exception as error:
        print(f"[ERROR]: {error}")
        sys.exit(1)


if __name__ == "__main__":
    pdf_file = input("Enter the absolute path of the PDF file you want to decrypt: ").strip()
    wordlist_file = os.path.expanduser('~/Hash_crackV2/wordlist.txt')
    crack_pdf(pdf_file, wordlist_file)
