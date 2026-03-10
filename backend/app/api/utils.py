from fastapi import APIRouter
import tkinter as tk
from tkinter import filedialog

router = APIRouter(prefix="/api/utils", tags=["utils"])

@router.get("/select-folder")
def select_folder():
    """Opens a native OS folder picker dialog."""
    try:
        root = tk.Tk()
        root.withdraw() # Hide main window
        root.attributes('-topmost', True) # Bring to front
        path = filedialog.askdirectory()
        root.destroy()
        return {"path": path}
    except Exception as e:
        return {"path": "", "error": str(e)}
