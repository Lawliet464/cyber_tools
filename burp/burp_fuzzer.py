from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
import random


# ===============================
# Extension principale pour Burp
# ===============================
class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Donne un nom à l’extension
        callbacks.setExtensionName("BHP Payload Generator")

        # On enregistre la factory pour Intruder
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return

    def getGeneratorName(self):
        return "BHP Payload Generator"

    def createNewInstance(self, attack):
        return BHPFuzzer(self, attack)


# ===============================
# Classe Fuzzer pour Intruder
# ===============================
class BHPFuzzer(IIntruderPayloadGenerator):

    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack

        # Limite du nombre de payloads à générer
        self.max_payloads = 10
        self.num_iterations = 0
        return

    # Burp demande : "On continue ?"
    def hasMorePayloads(self):
        if self.num_iterations == self.max_payloads:
            return False
        else:
            return True

    # Génération du prochain payload
    def getNextPayload(self, current_payload):
        # convertir les bytes en string
        payload = "".join(chr(x) for x in current_payload)

        # appliquer mutation
        payload = self.mutate_payload(payload)

        # incrémenter le compteur
        self.num_iterations += 1

        # renvoyer en bytes
        return payload.encode()

    def reset(self):
        self.num_iterations = 0
        return

    # =======================================
    # Mutateur ultra simple (à enrichir)
    # =======================================
    def mutate_payload(self, original_payload):
        # choisir aléatoirement une mutation
        picker = random.randint(1, 3)

        # choisir un offset dans la chaîne
        offset = random.randint(0, len(original_payload) - 1)
        front, back = original_payload[:offset], original_payload[offset:]

        # Cas 1 : injection SQL
        if picker == 1:
            front += "'"

        # Cas 2 : injection XSS
        elif picker == 2:
            front += "<script>alert('BHP!');</script>"

        # Cas 3 : répéter un morceau du payload
        elif picker == 3:
            if len(back) > 1:
                chunk_length = random.randint(0, len(back) - 1)
                repeater = random.randint(1, 10)
                for _ in range(repeater):
                    front += original_payload[:offset + chunk_length]

        return front + back
