#Python3
import re
import os
import fnmatch
import PySimpleGUI as sg

pattern = re.compile(r"\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}")
Bit_Keys = []
txt_Files = []

def walk():  #Walks the directory tree to find txt files
    for root, dirs, file in folder:
        for filename in file:
            if filename.endswith(('.txt', '.TXT')):  #filters to txt files
                txt_Files.append(os.path.join(root, filename))
      
def name_search():  #Finds txt files containing string
      
    for ele in txt_Files:
        if fnmatch.fnmatch(ele, "*BitLocker Recovery Key*"):
            print(ele + '\n')
            Bit_Keys.append(ele)

def string_search():  #Regex for key values
    
    for ele in txt_Files:
        try:
            with open(ele, 'r', encoding="utf-16-le") as text:
                text = text.read()
                k = re.findall(pattern, text)
                for key in k:
                    print(ele + " - " + key + '\n')
        except UnicodeDecodeError:
            pass
        except PermissionError:
            pass

sg.theme('LightGrey6')

layout = [  [sg.Text('Bitlocker Key Finder', size=(18, 1), font=('Impact', 20, 'bold italic'))],
            [sg.Text('Select Volume or Directory:')],
            [sg.Text('Source:'),sg.Input(key='SOURCE'), sg.FolderBrowse(key='SOURCE')],
            [sg.Checkbox('File Name Search', key="FILENAME"), sg.Checkbox('String Pattern Search', key="REG")],
            #[sg.Text('_'*82)],
            [sg.Output(size=(80,8),)],
            [sg.Button('Ok'), sg.Button('Exit'), sg.Text(' '*118), sg.Button('?', key='HELP')]]

# Create the Window
window = sg.Window('North Loop Consulting', layout, no_titlebar=False, alpha_channel=1, grab_anywhere=False)
# Event Loop to process "events" and get the "values" of the inputs

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit': # if user closes window or clicks cancel
        break
    elif event == 'HELP':
        sg.Popup("The tool seeks to find Bitlocker Recovery Keys using two methods.  \n\nThe first searches for filenames consistent with Recovery keys.  \n\nThe second method performs pattern searches in text files encoded in UTF 16 LE.")
    elif event == 'Ok':
        folder = os.walk(values["SOURCE"])
        print("Collecting directory structure data...")
        walk()
        if values["FILENAME"] == True:
            print("Searching for file names in " + values['SOURCE'])
            name_search()
        if values["REG"] == True:
            print("Conducting string search in " + values['SOURCE'])
            string_search()
        print("******  COMPLETE  *****")
    window.refresh()
window.close()
