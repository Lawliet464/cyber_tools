import contextlib
import os
import queue
import requests
import sys
import threading
import time

# Extensions de fichiers à ignorer
FILTERED = [".jpg", ".gif", ".png", ".css"]

# Cible distante
TARGET = "http://boodelyboo.com/wordpress"

# Nombre de threads à lancer
THREADS = 10

# Queues thread-safe
answers = queue.Queue()
web_paths = queue.Queue()


def gather_paths():
    """Parcourt localement l'installation WordPress et met les chemins dans web_paths."""
    for root, _, files in os.walk('.'):
        for fname in files:
            if os.path.splitext(fname)[1] in FILTERED:
                continue
            path = os.path.join(root, fname)
            if path.startswith('.'):
                path = path[1:]
            print(path)
            web_paths.put(path)


@contextlib.contextmanager
def chdir(path):
    """
    Change de répertoire pendant l'exécution, puis revient au répertoire d'origine.
    """
    this_dir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(this_dir)


def test_remote():
    """Teste chaque chemin trouvé localement sur la cible distante."""
    while not web_paths.empty():
        path = web_paths.get()
        url = f'{TARGET}{path}'
        time.sleep(2)  # Anti-bruteforce / throttling
        r = requests.get(url)
        if r.status_code == 200:
            answers.put(url)
            sys.stdout.write('+')
        else:
            sys.stdout.write('x')
        sys.stdout.flush()


def run():
    """Lance les threads pour tester les chemins distants."""
    mythreads = list()
    for i in range(THREADS):
        print(f'Spawning thread {i}')
        t = threading.Thread(target=test_remote)
        mythreads.append(t)
        t.start()

    for thread in mythreads:
        thread.join()


if __name__ == '__main__':
    # 1. Mapper les fichiers locaux
    with chdir("/chemin/vers/wordpress"):  # <-- À adapter
        gather_paths()

    # 2. Pause avant de lancer le scan
    input('Press return to continue.')

    # 3. Lancer le scan
    run()

    # 4. Sauvegarder les résultats
    with open('myanswers.txt', 'w') as f:
        while not answers.empty():
            f.write(f'{answers.get()}\n')

    print('done')
