import os
from getpass import getuser
import platform
import time,zipfile
print("[*] Checking Requirements Module....")
def get_encoder():
    print("INFO: For compatibility reasons with certain symbols, choose your encoder:")
    print("1) latin-1\n2) utf-8")
    encoder_text = input("option: ")
    select_encoder = "latin-1" if encoder_text == "1" else "utf-8"
    return select_encoder
def header():
    ascii_banner = pyfiglet.figlet_format("{ZIP CRACKER}").upper()
    print(colored(ascii_banner.rstrip("\n"), 'cyan', attrs=['bold']))
    print(colored("                                <Coded By: Clay>     \n", 'yellow', attrs=['bold']))
    print(colored("                                <Version: 2.0>     \n", 'magenta', attrs=['bold']))
    return
if platform.system().startswith("Linux"):
    try:
        from tqdm import tqdm
    except ImportError:
        os.system("python3 -m pip install tqdm -q -q -q")
        from tqdm import tqdm
    try:
        import termcolor
    except ImportError:
        os.system("python3 -m pip install termcolor -q -q -q")
        import termcolor
    from termcolor import colored
    try:
        import pyfiglet
    except ImportError:
        os.system("python3 -m pip install pyfiglet -q -q -q")
        import pyfiglet
def linuxpdf(encoder):
    os.system("clear")
    user=getuser()
    syst=os.path.exists("/data/data/com.termux/files/")
    if syst == True:
        output="/data/data/com.termux/files/home/Hash_crackV2/wordlist.txt"
    else:
        output=f"/home/{user}/Hash_crackV2/wordlist.txt"
    header()
    zip_filename = input(termcolor.colored("[*] Enter Your Rute zip file:- ", 'cyan')).strip()
    if not os.path.exists(zip_filename):
        print(termcolor.colored("\n[ X ] File " + zip_filename + " was not found, Provide Valid FileName And Path!",
                                'red'))
        exit()
    print(termcolor.colored("\n[*] Analyzing Zip File:- ", 'blue'), zip_filename)
    time.sleep(1)
    if zip_filename[-3:] == "zip":
        print(termcolor.colored("\n[ ✔ ] Valid ZIP File Found...", 'green'))
    else:
        print(termcolor.colored("\n[ X ] This is not a valid .zip file...\n", 'red'))
        exit()
    pwd_filename=output
    if not os.path.exists(pwd_filename):
        print(termcolor.colored("\n[ X ] File " + pwd_filename + " was not found, Provide Valid FileName And Path!",
                                'red'))
        exit()
    with open(pwd_filename, "rb" , errors='ignore') as passwords:
        passwords_list = passwords.readlines()
        total_passwords = len(passwords_list)
        my_zip_file = zipfile.ZipFile(zip_filename)
        for index, password in enumerate(passwords_list):
            try:
                my_zip_file.extractall(path="Extracted Folder", pwd=password.strip())
                print(colored("\n{***********************SUCCESS***********************}", 'green'))
                print(colored("[ ✔ ] ZIP FILE Password Found:- ", 'cyan'), password.decode(encoder).strip())
                break
            except KeyboardInterrupt:
                print()
            except:
                helo = round((index / total_passwords) * 100, 2)
                if helo == '100%':
                    print(colored("[ X ] ALL ATTEMPTS FAILED", 'red'))
                else:
                    print(colored(f"[*] Trying password:- {password.decode(encoder).strip()} ", 'green'))
                continue
def catc():
    try:
        encoder = get_encoder()
        time.sleep(1)
        os.system("clear")
        if platform.system().startswith("Linux"):
            linuxpdf(encoder)
    except KeyboardInterrupt:
        print(termcolor.colored("\nYou Pressed The Exit Button!", 'red'))
        quit()


catc()
