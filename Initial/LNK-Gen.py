#!/usr/bin/env python3
"""
GUI LNK Creator – Multiple Apps in One Shortcut (No Batch File)
Uses: cmd.exe /c start ... & start ...
"""

import os
import subprocess
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import win32com.client
import win32gui
import win32con
from PIL import Image, ImageTk
import ctypes

class LnkCreatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LNK Creator - Multi-App Shortcut")
        self.root.geometry("700x600")
        self.apps = []  # list of (exe_path, arguments)

        # ----- Output LNK path -----
        tk.Label(root, text="Save shortcut as (.lnk):").pack(anchor="w", padx=5, pady=2)
        self.output_frame = tk.Frame(root)
        self.output_frame.pack(fill="x", padx=5)
        self.output_path = tk.StringVar()
        self.output_entry = tk.Entry(self.output_frame, textvariable=self.output_path, width=50)
        self.output_entry.pack(side="left", fill="x", expand=True)
        tk.Button(self.output_frame, text="Browse...", command=self.browse_output).pack(side="right")

        # ----- Icon selection with preview -----
        icon_frame = tk.LabelFrame(root, text="Shortcut Icon", padx=5, pady=5)
        icon_frame.pack(fill="x", padx=5, pady=10)

        tk.Label(icon_frame, text="Icon source (file.dll,index):").grid(row=0, column=0, sticky="w", padx=2)
        self.icon_path = tk.StringVar(value=r"C:\Windows\System32\shell32.dll,1")
        self.icon_entry = tk.Entry(icon_frame, textvariable=self.icon_path, width=50)
        self.icon_entry.grid(row=0, column=1, padx=5, sticky="ew")
        tk.Button(icon_frame, text="Browse file...", command=self.browse_icon_file).grid(row=0, column=2, padx=2)
        tk.Button(icon_frame, text="Pick index...", command=self.pick_icon_index).grid(row=0, column=3, padx=2)

        self.preview_label = tk.Label(icon_frame, text="No preview", relief="sunken", width=15, height=5, bg="white")
        self.preview_label.grid(row=1, column=0, columnspan=2, pady=5, sticky="w")
        tk.Button(icon_frame, text="Preview Icon", command=self.preview_icon).grid(row=1, column=2, padx=5, pady=5)
        icon_frame.columnconfigure(1, weight=1)

        # ----- Application list -----
        tk.Label(root, text="Applications to launch (order preserved):").pack(anchor="w", padx=5, pady=(5,0))
        listbox_frame = tk.Frame(root)
        listbox_frame.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side="right", fill="y")
        self.listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set, height=6)
        self.listbox.pack(fill="both", expand=True)
        scrollbar.config(command=self.listbox.yview)
        self.listbox.bind("<Double-Button-1>", self.edit_selected)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Add App", command=self.add_app).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Remove Selected", command=self.remove_app).pack(side="left", padx=5)

        # ----- Options -----
        self.hide_cmd = tk.BooleanVar(value=True)
        tk.Checkbutton(root, text="Hide command prompt window (run minimized)", variable=self.hide_cmd).pack(anchor="w", padx=5)
        self.refresh_cache = tk.BooleanVar(value=True)
        tk.Checkbutton(root, text="Refresh icon cache (restart Explorer)", variable=self.refresh_cache).pack(anchor="w", padx=5)

        # ----- Create button -----
        tk.Button(root, text="CREATE SHORTCUT", command=self.create_shortcut,
                  bg="green", fg="white", font=("Arial", 10, "bold")).pack(pady=15)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------
    def browse_output(self):
        file = filedialog.asksaveasfilename(defaultextension=".lnk", filetypes=[("LNK files", "*.lnk")])
        if file:
            self.output_path.set(file)

    def add_app(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Application")
        dialog.geometry("500x150")
        tk.Label(dialog, text="Executable or file path:").pack(anchor="w", padx=5)
        exe_var = tk.StringVar()
        exe_entry = tk.Entry(dialog, textvariable=exe_var, width=60)
        exe_entry.pack(fill="x", padx=5)
        tk.Button(dialog, text="Browse...", command=lambda: self.browse_exe(exe_var)).pack(anchor="w", padx=5)

        tk.Label(dialog, text="Arguments (optional):").pack(anchor="w", padx=5, pady=(10,0))
        args_entry = tk.Entry(dialog, width=60)
        args_entry.pack(fill="x", padx=5)

        def save():
            exe = exe_var.get().strip()
            if not exe:
                messagebox.showerror("Error", "Path cannot be empty")
                return
            if not os.path.exists(exe):
                if not messagebox.askyesno("Warning", f"File not found:\n{exe}\nAdd anyway?"):
                    return
            args = args_entry.get().strip() or None
            self.apps.append((exe, args))
            self.update_listbox()
            dialog.destroy()

        tk.Button(dialog, text="Add", command=save).pack(pady=10)
        dialog.transient(self.root)
        dialog.grab_set()

    def browse_exe(self, var):
        file = filedialog.askopenfilename(title="Select File")
        if file:
            var.set(file)

    def edit_selected(self, event):
        idx = self.listbox.curselection()
        if not idx:
            return
        idx = idx[0]
        exe, args = self.apps[idx]
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Application")
        dialog.geometry("500x150")
        tk.Label(dialog, text="Executable or file path:").pack(anchor="w", padx=5)
        exe_var = tk.StringVar(value=exe)
        exe_entry = tk.Entry(dialog, textvariable=exe_var, width=60)
        exe_entry.pack(fill="x", padx=5)
        tk.Button(dialog, text="Browse...", command=lambda: self.browse_exe(exe_var)).pack(anchor="w", padx=5)

        tk.Label(dialog, text="Arguments (optional):").pack(anchor="w", padx=5, pady=(10,0))
        args_entry = tk.Entry(dialog, width=60)
        if args:
            args_entry.insert(0, args)
        args_entry.pack(fill="x", padx=5)

        def save():
            new_exe = exe_var.get().strip()
            if not new_exe:
                messagebox.showerror("Error", "Path cannot be empty")
                return
            new_args = args_entry.get().strip() or None
            self.apps[idx] = (new_exe, new_args)
            self.update_listbox()
            dialog.destroy()

        tk.Button(dialog, text="Save", command=save).pack(pady=10)
        dialog.transient(self.root)
        dialog.grab_set()

    def remove_app(self):
        selected = self.listbox.curselection()
        if selected:
            idx = selected[0]
            del self.apps[idx]
            self.update_listbox()

    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        for exe, args in self.apps:
            display = exe
            if args:
                display += f" {args}"
            self.listbox.insert(tk.END, display)

    # ------------------------------------------------------------------
    # Icon selection (unchanged from previous working version)
    # ------------------------------------------------------------------
    def browse_icon_file(self):
        file = filedialog.askopenfilename(
            title="Select icon library (DLL/EXE)",
            filetypes=[("Executables & Libraries", "*.exe *.dll"), ("All files", "*.*")]
        )
        if file:
            current = self.icon_path.get()
            idx = 0
            if ',' in current:
                try:
                    idx = int(current.split(',')[-1])
                except:
                    idx = 0
            self.icon_path.set(f"{file},{idx}")

    def pick_icon_index(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Choose icon index")
        dialog.geometry("450x180")
        tk.Label(dialog, text="Icon source file:").pack(anchor="w", padx=5)
        file_var = tk.StringVar(value=self.icon_path.get().split(',')[0] if ',' in self.icon_path.get() else self.icon_path.get())
        file_frame = tk.Frame(dialog)
        file_frame.pack(fill="x", padx=5)
        file_entry = tk.Entry(file_frame, textvariable=file_var, width=50)
        file_entry.pack(side="left", fill="x", expand=True)
        tk.Button(file_frame, text="Browse", command=lambda: self._browse_icon_file_for_picker(file_var)).pack(side="left")

        tk.Label(dialog, text="Resource index (0,1,2,...):").pack(anchor="w", padx=5, pady=(10,0))
        index_var = tk.IntVar(value=264)
        spin = tk.Spinbox(dialog, from_=0, to=9999, width=10, textvariable=index_var)
        spin.pack(anchor="w", padx=5)

        def apply():
            file_path = file_var.get().strip()
            if not file_path:
                messagebox.showerror("Error", "Please select a file")
                return
            self.icon_path.set(f"{file_path},{index_var.get()}")
            dialog.destroy()

        tk.Button(dialog, text="OK", command=apply).pack(pady=15)
        dialog.transient(self.root)
        dialog.grab_set()

    def _browse_icon_file_for_picker(self, var):
        file = filedialog.askopenfilename(title="Select icon file", filetypes=[("Executables/Libraries", "*.exe *.dll")])
        if file:
            var.set(file)

    # ------------------------------------------------------------------
    # Reliable icon preview (same as before)
    # ------------------------------------------------------------------
    def preview_icon(self):
        try:
            icon_spec = self.icon_path.get().strip()
            if ',' not in icon_spec:
                messagebox.showerror("Error", "Icon specification must be in format: file.dll,index")
                return

            file_path, idx_str = icon_spec.rsplit(',', 1)
            file_path = file_path.strip()
            try:
                index = int(idx_str.strip())
            except ValueError:
                messagebox.showerror("Error", "Index must be a number")
                return

            if not os.path.exists(file_path):
                messagebox.showerror("Error", f"File not found:\n{file_path}")
                return

            hicons = win32gui.ExtractIconEx(file_path, index, 1)
            hicon = hicons[0][0] if hicons[0] else (hicons[1][0] if hicons[1] else None)
            if not hicon:
                messagebox.showerror("Error", f"Icon index {index} not found")
                return

            icon_info = win32gui.GetIconInfo(hicon)
            hbm_color = icon_info[1]
            if hbm_color:
                bmp = win32ui.CreateBitmapFromHandle(hbm_color)
                width, height = bmp.GetInfo()['bmWidth'], bmp.GetInfo()['bmHeight']
                bmp.DeleteObject()
            else:
                width = height = 32

            hdc = win32gui.GetDC(0)
            # create DIB section
            class BITMAPINFOHEADER(ctypes.Structure):
                _fields_ = [
                    ("biSize", ctypes.c_uint),
                    ("biWidth", ctypes.c_int),
                    ("biHeight", ctypes.c_int),
                    ("biPlanes", ctypes.c_ushort),
                    ("biBitCount", ctypes.c_ushort),
                    ("biCompression", ctypes.c_uint),
                    ("biSizeImage", ctypes.c_uint),
                    ("biXPelsPerMeter", ctypes.c_int),
                    ("biYPelsPerMeter", ctypes.c_int),
                    ("biClrUsed", ctypes.c_uint),
                    ("biClrImportant", ctypes.c_uint)
                ]
            class BITMAPINFO(ctypes.Structure):
                _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", ctypes.c_uint * 3)]

            bmi_header = BITMAPINFOHEADER()
            bmi_header.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bmi_header.biWidth = width
            bmi_header.biHeight = -height
            bmi_header.biPlanes = 1
            bmi_header.biBitCount = 32
            bmi_header.biCompression = 0
            bmi = BITMAPINFO()
            bmi.bmiHeader = bmi_header

            bits_ptr = ctypes.POINTER(ctypes.c_ubyte)()
            hbmp = win32gui.CreateDIBSection(hdc, bmi, win32con.DIB_RGB_COLORS, ctypes.byref(bits_ptr), None, 0)
            if not hbmp:
                raise Exception("CreateDIBSection failed")

            mem_dc = win32gui.CreateCompatibleDC(hdc)
            old_bmp = win32gui.SelectObject(mem_dc, hbmp)
            win32gui.DrawIconEx(mem_dc, 0, 0, hicon, width, height, 0, 0, win32con.DI_NORMAL)

            buffer_size = width * height * 4
            buffer = ctypes.create_string_buffer(buffer_size)
            ctypes.memmove(buffer, bits_ptr, buffer_size)
            bits = buffer.raw

            img = Image.frombuffer("BGRA", (width, height), bits, "raw", "BGRA", 0, 1)

            win32gui.SelectObject(mem_dc, old_bmp)
            win32gui.DeleteDC(mem_dc)
            win32gui.DeleteObject(hbmp)
            win32gui.ReleaseDC(0, hdc)
            win32gui.DestroyIcon(hicon)

            img.thumbnail((64, 64), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self.preview_label.config(image=photo, text="")
            self.preview_label.image = photo

        except Exception as e:
            messagebox.showerror("Preview Error", str(e))
            self.preview_label.config(image="", text="Preview failed")
            self.preview_label.image = None

    # ------------------------------------------------------------------
    # Create shortcut without batch file
    # ------------------------------------------------------------------
    def create_shortcut(self):
        output = self.output_path.get().strip()
        if not output:
            messagebox.showerror("Error", "Please select output LNK path")
            return
        if not output.lower().endswith(".lnk"):
            output += ".lnk"

        if not self.apps:
            messagebox.showerror("Error", "Add at least one application")
            return

        # Build a single command line for cmd.exe /c
        # Example: /c start "" "app1" args1 & start "" "app2" args2
        commands = []
        for exe, args in self.apps:
            # Quote the executable path if it contains spaces
            exe_quoted = f'"{exe}"' if ' ' in exe else exe
            if args:
                commands.append(f'start "" {exe_quoted} {args}')
            else:
                commands.append(f'start "" {exe_quoted}')
        cmd_line = " /c " + " & ".join(commands)

        # Shortcut target is cmd.exe
        cmd_exe = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "cmd.exe")

        # Icon selection
        icon_spec = self.icon_path.get().strip()
        if ',' not in icon_spec:
            messagebox.showerror("Error", "Icon must be in format: file.dll,index")
            return

        try:
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortcut(output)
            shortcut.TargetPath = cmd_exe
            shortcut.Arguments = cmd_line
            shortcut.WorkingDirectory = os.path.dirname(cmd_exe)  # system32
            shortcut.IconLocation = icon_spec

            # Hide the console window if requested
            if self.hide_cmd.get():
                shortcut.WindowStyle = 7  # SW_SHOWMINNOACTIVE (minimized)
            else:
                shortcut.WindowStyle = 1  # SW_SHOWNORMAL

            shortcut.Save()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create shortcut:\n{e}")
            return

        if self.refresh_cache.get():
            subprocess.run("ie4uinit.exe -show", shell=True, capture_output=True)
            time.sleep(0.5)
            subprocess.run("taskkill /f /im explorer.exe", shell=True, capture_output=True)
            time.sleep(1)
            subprocess.run("start explorer.exe", shell=True)

        messagebox.showinfo("Success", f"Shortcut created:\n{output}\n\nIt will run all programs in order.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LnkCreatorApp(root)
    root.mainloop()
