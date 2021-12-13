#Python3
#Bitlocker_Key_FinderGUI
import re
import os
import fnmatch
import shutil
import PySimpleGUI as sg

pattern = re.compile(r"\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}")
Bit_Keys = []
txt_Files = []

def walk():  #Walks the directory tree to find txt files
    for root, dirs, file in folder:
        for filename in file:
            if filename.endswith(('.txt', '.TXT', '.bek', '.BEK')):  #filters to txt and bek files
                txt_Files.append(os.path.join(root, filename))      #creates list of txt and bek files
      
def name_search():  #Finds txt and bek files and adds them to the bit_keys list
      
    for ele in txt_Files:
        if fnmatch.fnmatch(ele, "*BitLocker Recovery Key*"):
            print(ele + '\n')
            Bit_Keys.append(ele)
        if fnmatch.fnmatch(ele, "*.BEK"):
            print(ele + '\n')
            Bit_Keys.append(ele)

def string_search():  #Regex for key values
    for ele in txt_Files:
        try:
            with open(ele, 'r', encoding="utf-16-le") as text:      #this encoding is the default used by Microsoft in creating the txt files
                text = text.read()
                k = re.findall(pattern, text)
                for key in k:
                    Bit_Keys.append(ele)
                    print(ele + " - " + key + '\n')
        except UnicodeDecodeError:                              
            pass
        except PermissionError:
            pass

def copy_key_files():   #COPIES THE KEYS FROM BIT_KEYS LIST TO USER SELECTED DIRECTORY
    destination = values['OUTPUT']
    print("*** COPYING KEY RELATED FILES... ***")
    copy_list = []
    for i in Bit_Keys:      #create a unique list of paths to avoid copy errors in monitor window
        if i not in copy_list:
            copy_list.append(i)
    try:
        for key_File in copy_list:
            shutil.copy(key_File, destination)

    except Exception:
        print(key_File +' - Error Copying- check for user access to file or name collision in destination')
        pass   
    print("\n*** FILES COPIED TO DESTINATION DIRECTORY. ***\n")

sg.theme('Reddit')

layout = [  [sg.Text('Bitlocker Key Finder', size=(18, 1), font=('Impact', 20, 'bold italic'))],
            [sg.Text('Select Volume or Directory to search:')],
            [sg.Text('Source:'),sg.Input(key='SOURCE',), sg.FolderBrowse(key='SOURCE')],
            [sg.Checkbox('File Name Search', key="FILENAME"), sg.Checkbox('String Pattern Search', key="REG")],
            #[sg.Text('_'*82)],
            [sg.Checkbox('Copy responsive files to directory: ', enable_events=True ,key="COPYSWITCH")], 
            [sg.Input(key='OUTPUT', disabled=True), sg.FolderBrowse(key='OUTPUT1', enable_events=True, disabled=True)],
            [sg.Output(size=(80,8),)],
            [sg.Button('Ok'), sg.Button('Exit'), sg.Text(' '*118), sg.Button('?', key='HELP')]]

# Create the Window
window = sg.Window('North Loop Consulting', layout, no_titlebar=False, alpha_channel=1, grab_anywhere=False)
# Event Loop to process "events" and get the "values" of the inputs

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit': # if user closes window or clicks cancel
        break
    if values['COPYSWITCH'] == True:                #Enable/Disable file output directory
        window['OUTPUT'].update(disabled=False)
        window['OUTPUT1'].update(disabled=False)
    if values['COPYSWITCH'] == False:
        window['OUTPUT'].update(disabled=True)
        window['OUTPUT1'].update(disabled=True)
    if event == 'HELP':
        sg.Popup("The tool seeks to find Bitlocker Recovery Keys using two methods.  \n\nThe first method searches for filenames consistent with Recovery Key files including .TXT and .BEK file extensions. This method returns the file's path. \n\nThe second method performs pattern searches for key values in text files encoded in UTF 16 LE. This method returns the file's path and the string hit.\n\nIf you are running both methods, expect duplicate file hits. \n\nFiles meeting your search criteria can be saved to an output folder of your choice. \n\nCopyright 2021 North Loop Consulting")
        window.refresh()
    elif event == 'Ok':
        folder = os.walk(values["SOURCE"])
        print("*** SEARCHING FOR KEY FILES... ***")
        walk()
        if values["FILENAME"] == True:
            print("Searching for file names in " + values['SOURCE'])
            name_search()
        if values["REG"] == True:
            print("Conducting string search in " + values['SOURCE'])
            string_search()
        if values['COPYSWITCH'] == True:
            copy_key_files()
        print("\n******  COMPLETE  ******")
    window.refresh()
window.close()
