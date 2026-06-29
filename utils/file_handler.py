from tkinter import filedialog


class FileHandler:

    @staticmethod
    def save_file(data):

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )

        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(data)

    @staticmethod
    def open_file():

        file_path = filedialog.askopenfilename(
            filetypes=[
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )

        if file_path:
            with open(file_path, "r", encoding="utf-8") as file:
                return file.read()

        return ""