# Bitlocker_Key_Finder

*As mentioned in Thisweekin4n6. How cool is that!?!

A digital forensic solution for addressing Bitlocker credentials.

This tool automates the search for TXT and BEK files containing Bitlocker Recovery Keys.  It can search based on file name or patterns within relevant text files.
The intended use case is for forensic work necessitating such a search.

v1.0 is a Python 3 script to locate Bitlocker Recovery Key text files.

The only input required is the volume or directory to be searched.  Provide a volume or absolute path to a directory.
After searching for relevant file names, a string search can be performed on text file contents in the event a Recovery Key document has been renamed.

Usage:  
python Bitlocker_Key_Finder.py 'volume or directory'  
python Bitlocker_Key_Finder.py C:\\  
python Bitlocker_Key_Finder.py "C:\Users\user\Documents"

The script returns all findings to the command prompt.

The GUI can be found in v2.1 and higher and includes additional functionality.

![alt text](https://github.com/user-attachments/assets/adc3a22c-545b-4fa2-9bfe-fea5899bd4fa)

Like the script, the GUI seeks saved Recovery Key files in both TXT and BEK formats.  It also recovers keys for mounted volumes on active systems. 

As of v3.0, opening the tool presents the user interface window (see above) and an output console window. Closing one window will close both of the windows.

Recovering keys for mounted volumes requires admin permissions. If you forget and attempt to use a function needing admin access, the tool will prompt you to restart it with elevated permissions.

Identified TXT and BEK files can be copied to a location chosen by the user.  This same output location will be used to store a report for key information related to mounted volumes on the target system.

Copied BEK files are visible. 

![alt text](https://user-images.githubusercontent.com/73806121/149680779-97783cc9-9edc-4ff7-907d-48ed21961dfd.png)

Reporting is intended to describe the tool used, date/time of use, user account utilized to collect key data on mounted and accessible volumes.

Please let me know if you run into any issues or have suggestions for the tool.
