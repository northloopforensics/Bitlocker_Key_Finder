# Bitlocker_Key_Finder

This tool automates the search for TXT and BEK files containing Bitlocker Recovery Keys.  It can search based on file name or patterns within relevant text files.
The intended use case is for forensic work necessitating such a search.


v1.0 is a Python 3 script to locate Bitlocker Recovery Key text files.

The only input required is the volume or directory to be searched.  Provide a volume or absolute path to a directory.
After searching for relevant file names, a string search can be performed on text file contents.
All responses are printed to the command prompt.

Usage:  
python Bitlocker_Key_Finder.py 'volume or directory'  
python Bitlocker_Key_Finder.py C:\\  
python Bitlocker_Key_Finder.py "C:\Users\user\Documents"

The script returns all findings to the command prompt.

The GUI can be found in v2.1

![alt text](https://user-images.githubusercontent.com/73806121/146647880-924003d1-e942-4da6-9189-16939425c021.png)

The executable performs the same actions as the script in a GUI interface.  Returned findings are visible in the interface. 

The GUI is also able to copy returned files to a location of the user's choice for triage use.

Copied BEK files are visible. 

Please let me know if you run into any issues or have suggestions for the tool.
