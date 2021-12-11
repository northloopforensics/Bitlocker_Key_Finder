#Python3

import re
import os
import fnmatch
import argparse

_author_ = ['Copyright 2021 North Loop Consulting']
_copy_ = ['(C) 2021']
_description_ = ("---Bitlocker_Key_Finder v1.0---"
                 " A tool to locate and retrieve Bitlocker Recovery files."
                 " Searches file names and file content for recovery keys."
                 )

parser = argparse.ArgumentParser(
    description=_description_,
    epilog="{}".format(
        ", ".join(_author_), _copy_))

parser.add_argument("INPUT_VOLUME", help="Input volume letter - ex. 'C:\\\\' or Absolute path - ex. 'E:\\Evidence\\MountedImage\\C'")
args = parser.parse_args()

In_Vol = args.INPUT_VOLUME

txt_Files = []
for root, dirs, file in os.walk(In_Vol):
    for filename in file:
    
        if filename.endswith(('.txt', '.TXT')):  #filters to txt files
            txt_Files.append(os.path.join(root, filename))
pattern = re.compile(r"\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}")
Bit_Keys = []
for ele in txt_Files:
    if fnmatch.fnmatch(ele, "*BitLocker Recovery Key*"):
        print(ele)
        Bit_Keys.append(ele)
    if fnmatch.fnmatch(ele, "*.BEK"):
            print(ele + '\n')
            Bit_Keys.append(ele)

if len(Bit_Keys) == 0:
    print("""***************************************************************************
        \nNo Bitlocker Recovery text files were found. 
        \nWould you like to perform a string search on all text files (slow process)?
        \n***************************************************************************""")
    choice = input("'Yes' or 'No':  ") 
    if choice == 'Yes' or "Yes " or "yes" or "yes ":
        for ele in txt_Files:
            try:
                with open(ele, 'r', encoding="utf-16-le") as text:
                    text = text.read()
                    k = re.findall(pattern, text)
                    for key in k:
                        print(ele + " - " + key)
            except UnicodeDecodeError:
                pass
            except PermissionError:
                pass
        
if len(Bit_Keys) >= 1:
    print("""++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
           \nGREAT JOB!!! YOU FOUND SOME! 
           \nWould you like to continue and search the contents of all text files (slower process)?
           \n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++""")
    choice = input("'Yes' or 'No':  ") 
    if choice == 'Yes' or "Yes " or "yes" or "yes ":
        for ele in txt_Files:
            try:
                with open(ele, 'r', encoding="utf-16-le") as text:
                    text = text.read()
                    k = re.findall(pattern, text)
                    for key in k:
                        print(ele + " - " + key)
            except UnicodeDecodeError:
                pass
            except PermissionError:
                pass
