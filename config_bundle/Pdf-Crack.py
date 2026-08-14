#!/usr/bin/env python3

import pikepdf
import sys
import os
import signal
from multiprocessing import Pool, cpu_count

def init_worker():
   signal.signal(signal.SIGINT, signal.SIG_IGN)
   signal.signal(signal.SIGTSTP, signal.SIG_IGN)


def try_passwords(args):
    pdf_file, passwords = args
    for pwd in passwords:
        try:
            with pikepdf.open(pdf_file, password=pwd) as pdf:
                pdf.save("pdf_decryption.pdf")
                print("\n" + "=" * 50)
                print("=" * 50)
                print("[ PASSWORD FOUND ]".center(50))
                print("=" * 50)
                print(f">>> Recovered Password: {pwd}".center(50))
                print("=" * 50 + "\n")
                if pwd != pwd.strip():
                   print("[WARNING]: The password contains leading or trailing whitespace")               
                return True

        except pikepdf.PasswordError:
            continue

        except Exception as error_:
            print(f"[ERROR]: {error_}")
            return True # returns a false positive to stop the code due to the given exception

    return None


def main(pdf_file, wordlist_file):
    try:
      read_block_size = 8 * 1024 * 1024
      process_count = max(1, cpu_count() - 1)
      result = None
      with Pool(processes=process_count, initializer=init_worker ) as pool:
        with open(wordlist_file, 'r', encoding="utf-8", errors='ignore') as keywords_read:
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

                tasks = [
                   (pdf_file, chunk)
                     for chunk in chunks[:actual_processes]
                   ]

                for result in pool.imap_unordered(try_passwords, tasks):
                    if result:
                       pool.terminate()
                       return

            if last_line:
                   result = try_passwords((pdf_file, [last_line]))
                   if result:
                      return
      
      print("[FINISH]>> PASSWORD NOT FOUND")

    
    except KeyboardInterrupt:
        print()
        sys.exit(0)


    except Exception as error:
        print(f"[ERROR]: {error}")
        sys.exit(1)


if __name__ == "__main__":
  try:
    pdf_file = input("Enter the absolute path of the PDF file you want to decrypt: ").strip()
    wordlist_file = os.path.expanduser('~/Hash_crackV2/wordlist.txt')
    main(pdf_file, wordlist_file)
     
  except KeyboardInterrupt:
      print()
      sys.exit(0)

  except FileNotFoundError as f:
        print(f"[ERROR]: File not found {f}")
        sys.exit(1)
