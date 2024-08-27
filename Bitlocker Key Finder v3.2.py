import re
import os
import fnmatch
import shutil
import subprocess
import string
import ctypes
import chardet
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading

pattern = re.compile(r"\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}")
Bit_Keys = []
txt_Files = []
now = datetime.datetime.now()

# STARTUPINFO to hide the command window
startupinfo = subprocess.STARTUPINFO()
startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
startupinfo.wShowWindow = subprocess.SW_HIDE

def isAdmin():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

def walk(folder):
    for root, dirs, files in os.walk(folder):
        for filename in files:
            if filename.endswith(('.txt', '.TXT', '.bek', '.BEK')):
                txt_Files.append(os.path.join(root, filename))

def name_search(gui):
    for ele in txt_Files:
        if fnmatch.fnmatch(ele, "*BitLocker Recovery Key*"):
            Bit_Keys.append(ele)
            gui.log_message(f"Found BitLocker Recovery Key file: {ele}", "success")
        if fnmatch.fnmatch(ele, "*.BEK"):
            Bit_Keys.append(ele)
            gui.log_message(f"Found BEK file: {ele}", "success")

def exhaustive_string_search(gui):
    for ele in txt_Files:
        try:
            if not os.path.exists(ele):
                gui.log_message(f"File not found: {ele}", "warning")
                continue
            
            too_big = os.path.getsize(ele)
            if too_big >= 1048576:  # Skip files larger than 1MB
                print(f"File too large (>1MB), skipping: {ele}", "warning")
                continue

            # Read the raw contents of the file
            with open(ele, 'rb') as raw_file:
                raw_content = raw_file.read()

            # Detect the encoding
            detected = chardet.detect(raw_content)
            encoding = detected['encoding']

            try:
                decoded_content = raw_content.decode(encoding)
                k = re.findall(pattern, decoded_content)
                for key in k:
                    Bit_Keys.append(ele)
                    gui.log_message(f"Found BitLocker key in file: {ele}", "success")
                    gui.log_message(f"Key: {key}", "info")
            except UnicodeDecodeError:
                gui.log_message(f"Unable to decode file as {encoding}: {ele}", "warning")
            
        except FileNotFoundError:
            gui.log_message(f"File not found: {ele}", "warning")
        except PermissionError:
            gui.log_message(f"Permission denied: {ele}", "warning")
        except Exception as e:
            print(f"Error processing file {ele}: {str(e)}", "error")

def UTF16LE_string_search(gui):
    for ele in txt_Files:
        try:
            if not os.path.exists(ele):
                gui.log_message(f"File not found: {ele}", "warning")
                continue
            
            too_big = os.path.getsize(ele)
            if too_big >= 1048576:  # Skip files larger than 1MB
                print(f"File too large (>1MB), skipping: {ele}", "warning")
                continue

            # Read the raw contents of the file
            with open(ele, 'rb') as raw_file:
                raw_content = raw_file.read()

            # # Detect the encoding
            # detected = chardet.detect(raw_content)
            # encoding = detected['encoding']

            # if encoding == 'utf-16-le':
            try:
                decoded_content = raw_content.decode('utf-16-le')
                k = re.findall(pattern, decoded_content)
                for key in k:
                    Bit_Keys.append(ele)
                    gui.log_message(f"Found BitLocker key in file: {ele}", "success")
                    gui.log_message(f"Key: {key}", "info")
            except UnicodeDecodeError:
                # gui.log_message(f"Unable to decode file as UTF-16LE: {ele}", "warning")
                pass
            else:
                print(f"File is not UTF-16LE encoded, skipping: {ele}", "info")

        except FileNotFoundError:
            gui.log_message(f"File not found: {ele}", "warning")
        except PermissionError:
            gui.log_message(f"Permission denied: {ele}", "warning")
        except Exception as e:
            gui.log_message(f"Error processing file {ele}: {str(e)}", "error")

class BitlockerKeyFinderGUI:
    def __init__(self, master):
        self.master = master
        master.title("North Loop Consulting - Bitlocker Key Finder v3.2")
        master.geometry("800x600")
        master.configure(bg="#f0f0f0")

        self.create_widgets()
        self.master.after(100, self.periodic_refresh)  # Start periodic refresh

    def create_widgets(self):
        # Title
        # title_frame = tk.Frame(self.master, bg="#f0f0f0")
        # title_frame.pack(pady=10)
        # tk.Label(title_frame, text="Bitlocker Key Finder", font=("Arial", 24, "bold"), bg="#f0f0f0").pack()

        # Find Saved Bitlocker .TXT and .BEK Files
        tk.Label(self.master, text="Find Saved Bitlocker .TXT and .BEK Files", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(pady=5)

        # Source Directory
        source_frame = tk.Frame(self.master, bg="#f0f0f0")
        source_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(source_frame, text="Select Volume or Directory to Search:", bg="#f0f0f0").pack(side="left")
        self.source_entry = tk.Entry(source_frame, width=50)
        self.source_entry.pack(side="left", expand=True, fill="x", padx=5)
        tk.Button(source_frame, text="Browse", command=self.browse_source, bg="#4CAF50", fg="white", relief=tk.RAISED).pack(side="left")

        # Checkboxes for search options
        checkbox_frame = tk.Frame(self.master, bg="#f0f0f0")
        checkbox_frame.pack(pady=5)
        self.filename_var = tk.BooleanVar()
        tk.Checkbutton(checkbox_frame, text="File Name Search (Fast)", variable=self.filename_var, bg="#f0f0f0").pack(side="left")

        self.utf16le_search_var = tk.BooleanVar()
        tk.Checkbutton(checkbox_frame, text="UTF-16LE String Search", variable=self.utf16le_search_var, bg="#f0f0f0").pack(side="left")

        self.exhaustive_search_var = tk.BooleanVar()
        tk.Checkbutton(checkbox_frame, text="Exhaustive String Search (Slow)", variable=self.exhaustive_search_var, bg="#f0f0f0").pack(side="left")

        # Copy Files Option
        self.copy_var = tk.BooleanVar()
        tk.Checkbutton(self.master, text="Copy responsive files to Output Directory", variable=self.copy_var, bg="#f0f0f0").pack(pady=5)

        # Recover Keys from Current Machine
        tk.Label(self.master, text="Recover Keys from Current Machine", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(pady=5)
        self.mgbde_var = tk.BooleanVar()
        tk.Checkbutton(self.master, text="ADMIN ONLY - Save keys for mounted volumes to Output Directory", variable=self.mgbde_var, bg="#f0f0f0").pack()

        # Output Directory
        output_frame = tk.Frame(self.master, bg="#f0f0f0")
        output_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(output_frame, text="Output Directory:", font=("Arial", 11, "bold"), bg="#f0f0f0").pack(side="left")
        self.output_entry = tk.Entry(output_frame, width=50)
        self.output_entry.pack(side="left", expand=True, fill="x", padx=5)
        self.output_entry.insert(0, os.getcwd())
        tk.Button(output_frame, text="Browse", command=self.browse_output, bg="#4CAF50", fg="white", relief=tk.RAISED).pack(side="left")

        # Buttons
        button_frame = tk.Frame(self.master, bg="#f0f0f0")
        button_frame.pack(pady=10)
        self.find_keys_button = tk.Button(button_frame, text="Find Keys", command=self.start_find_keys_thread, bg="#2196F3", fg="white", relief=tk.RAISED)
        self.find_keys_button.pack(side="left", padx=5)
        
        tk.Button(button_frame, text="Help", command=self.show_help, bg="orange", fg="black", relief=tk.RAISED).pack(side="left", padx=5)

        # Console
        console_frame = tk.Frame(self.master, bg="#333333")
        console_frame.pack(fill="both", expand=True, padx=10, pady=5)
        # tk.Label(console_frame, text="Console Output", font=("Arial", 12, "bold"), bg="#333333", fg="white").pack()
        self.console = tk.Text(console_frame, wrap="word", height=15, bg="#ffffff", fg="white")
        self.console.pack(fill="both", expand=True)
        self.console.tag_configure("info", foreground="blue")
        self.console.tag_configure("warning", foreground="orange")
        self.console.tag_configure("error", foreground="red")
        self.console.tag_configure("success", foreground="black")
        self.console.tag_configure("bold", font=("Arial", 10,))

        clear_frame = tk.Frame(self.master, bg="#f0f0f0")
        clear_frame.pack(fill="x", padx=10, pady=(0, 10))  # Add padding at the bottom
        tk.Button(clear_frame, text="Clear Window", command=self.clear_console, bg="#FF5722", fg="white", relief=tk.RAISED).pack()


    def browse_source(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, folder_path)

    def browse_output(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, folder_path)

    def show_help(self):
        help_message = (
            "North Loop Consulting - Bitlocker Key Finder\n\n"
            "1. Select the directory to search for Bitlocker Recovery Keys or BEK files.\n"
            "2. Choose search options:\n"
            "   - File Name Search: Quickly finds files with specific names.\n"
            "   - UTF-16LE String Search: Searches for Bitlocker keys in UTF-16LE encoded files.\n"
            "   - Exhaustive String Search: Performs a thorough search but is slower.\n"
            "     *String search occurs in files smaller than 1MB\n"
            "3. Optionally, enable the Copy Files option to copy found files to the output directory.\n"
            "4. Optionally, enable the recovery of keys from the current machine (ADMIN ONLY).\n"
            "5. Choose the output directory to save results.\n"
            "6. Click 'Find Keys' to start the search."
        )
        messagebox.showinfo("Help", help_message)

    def start_find_keys_thread(self):
        # Disable the Find Keys button
        self.find_keys_button.config(state=tk.DISABLED)
        # Start the find keys process in a separate thread
        thread = threading.Thread(target=self.find_keys)
        thread.start()

    def find_keys(self):
        global Bit_Keys, txt_Files
        Bit_Keys = []
        txt_Files = []
        folder_path = self.source_entry.get()
        
        # Check directory validity
        # if not os.path.isdir(folder_path):
        #     self.log_message("Invalid directory path. Please select a valid directory.", "warning")
        #     # Re-enable the Find Keys button
        #     self.find_keys_button.config(state=tk.NORMAL)
        #     return

        # Traverse the directory and find .txt and .BEK files
        walk(folder_path)

        if self.filename_var.get():
            self.log_message(f"Searching for file names in {folder_path}", "info")
            name_search(self)

        if self.exhaustive_search_var.get():
            self.log_message(f"Conducting exhaustive string search in {folder_path}", "info")
            exhaustive_string_search(self)

        if self.utf16le_search_var.get():
            self.log_message(f"Conducting UTF-16LE string search in {folder_path}", "info")
            UTF16LE_string_search(self)

        self.log_message(f"Total BitLocker keys/files found: {len(Bit_Keys)}", "success")
        
        if self.copy_var.get():
            self.copy_key_files()
        
        if self.mgbde_var.get():
            self.get_active_keys()
        
        self.log_message("SEARCH COMPLETE", "success")
        
        # Re-enable the Find Keys button
        self.find_keys_button.config(state=tk.NORMAL)

    def copy_key_files(self):
        output_folder = self.output_entry.get()
        if not os.path.isdir(output_folder):
            self.log_message("Invalid output directory. Please select a valid directory.", "warning")
            return
        for file in Bit_Keys:
            try:
                shutil.copy(file, output_folder)
                self.log_message(f"Copied file: {file}", "success")
            except Exception as e:
                self.log_message(f"Error copying file {file}: {str(e)}", "error")

    def get_active_keys(self):
        if not isAdmin():
            self.log_message("Admin rights are required to retrieve BitLocker keys.", "warning")
            return

        output_folder = self.output_entry.get()
        if not os.path.isdir(output_folder):
            self.log_message("Invalid output directory. Please select a valid directory.", "warning")
            return
        
        try:
            volumes = subprocess.check_output(["manage-bde", "-status"], startupinfo=startupinfo).decode("utf-8")
            volume_lines = volumes.splitlines()
            for line in volume_lines:
                if "Volume" in line:
                    volume = line.split()[1]
                    try:
                        recovery_keys = subprocess.check_output(["manage-bde", "-protectors", "-get", volume], startupinfo=startupinfo).decode("utf-8")
                        with open(os.path.join(output_folder, f"{volume}_keys.txt"), "w") as key_file:
                            key_file.write(recovery_keys)
                            self.log_message(f"Copied BitLocker key for volume {volume}", "success")
                    except subprocess.CalledProcessError:
                        self.log_message(f"Failed to retrieve keys for volume {volume}", "warning")
        except Exception as e:
            self.log_message(f"Error retrieving BitLocker keys: {str(e)}", "error")

    def log_message(self, message, level="info"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        self.console.insert(tk.END, formatted_message, (level, "bold"))
        self.console.see(tk.END)
        self.master.after(100, lambda: self.master.update_idletasks())  # Regular GUI update

    def clear_console(self):
        self.console.delete(1.0, tk.END)

    def periodic_refresh(self):
        self.master.update_idletasks()
        self.master.after(100, self.periodic_refresh)

# Create and run the Tkinter application
root = tk.Tk()
app = BitlockerKeyFinderGUI(root)
root.mainloop()