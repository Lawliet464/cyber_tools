from ctypes import byref, c_uint, c_ulong, sizeof, Structure, windll
import random
import sys
import time
import win32api

# Structure pour récupérer le dernier événement utilisateur
class LASTINPUTINFO(Structure):
    _fields_ = [
        ('cbSize', c_uint),
        ('dwTime', c_ulong)
    ]

# Fonction pour obtenir le temps écoulé depuis le dernier input
def get_last_input():
    struct_lastinputinfo = LASTINPUTINFO()
    struct_lastinputinfo.cbSize = sizeof(LASTINPUTINFO)  # Initialisation obligatoire
    windll.user32.GetLastInputInfo(byref(struct_lastinputinfo))  # Remplit la structure

    run_time = windll.kernel32.GetTickCount()  # Temps écoulé depuis le démarrage de Windows
    elapsed = run_time - struct_lastinputinfo.dwTime
    print(f"[*] It's been {elapsed} milliseconds since the last event.")
    return elapsed

# Classe pour détecter frappes clavier et clics souris
class Detector:
    def __init__(self):
        self.double_clicks = 0
        self.keystrokes = 0
        self.mouse_clicks = 0

    # Détecte les frappes et clics
    def get_key_press(self):
        for i in range(0, 0xff):  # Parcours toutes les touches virtuelles
            state = win32api.GetAsyncKeyState(i)
            if state & 0x0001:  # Si la touche a été pressée
                if i == 0x1:  # Clic gauche
                    self.mouse_clicks += 1
                    return time.time()  # Retourne timestamp pour timing
                elif 32 < i < 127:  # Caractères ASCII imprimables
                    self.keystrokes += 1
        return None

    # Boucle principale de détection sandbox
    def detect(self):
        previous_timestamp = None
        first_double_click = None
        double_click_threshold = 0.35  # seuil pour un double clic

        max_double_clicks = 10
        max_keystrokes = random.randint(10, 25)
        max_mouse_clicks = random.randint(5, 25)
        max_input_threshold = 30000  # ms

        last_input = get_last_input()
        if last_input >= max_input_threshold:
            sys.exit(0)  # Si aucun input récent, sortie (possible sandbox)

        detection_complete = False
        while not detection_complete:
            keypress_time = self.get_key_press()
            if keypress_time is not None and previous_timestamp is not None:
                elapsed = keypress_time - previous_timestamp
                if elapsed <= double_click_threshold:
                    self.mouse_clicks -= 2
                    self.double_clicks += 1
                    if first_double_click is None:
                        first_double_click = time.time()
                else:
                    if self.double_clicks >= max_double_clicks:
                        if (keypress_time - first_double_click <=
                                (max_double_clicks * double_click_threshold)):
                            sys.exit(0)  # Exit si comportement suspect

                if (self.keystrokes >= max_keystrokes and
                    self.double_clicks >= max_double_clicks and
                    self.mouse_clicks >= max_mouse_clicks):
                    detection_complete = True

                previous_timestamp = keypress_time
            elif keypress_time is not None:
                previous_timestamp = keypress_time

if __name__ == '__main__':
    d = Detector()
    d.detect()
    print('okay.')
