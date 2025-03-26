import socket
import threading
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import base64

HEADER = 64
PORT = 5044
SERVER_IP = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER_IP, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
BAD_NAME = "Username is not Available"
username = None

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def codec(msg, a):
    return msg.encode(FORMAT) if a else msg.decode(FORMAT)

def send(msg, cipher=None):
    if cipher:  # Verschlüsselte Nachricht
        message = cipher.encrypt(codec(msg, True))
        send_length = codec(str(len(message)), True)
        send_length += b" " * (HEADER - len(send_length))
        client.send(send_length)
        client.send(message)
    else:  # Für DH ohne Verschlüsselung
        message = codec(msg, True)
        send_length = codec(str(len(message)), True)
        send_length += b" " * (HEADER - len(send_length))
        client.send(send_length)
        client.send(message)

def process_message(cipher):
    try:
        msg_length = client.recv(HEADER).decode(FORMAT).strip()
        if not msg_length:
            raise ValueError("Kein Header empfangen")
        msg_length = int(msg_length)
        msg = client.recv(msg_length)
        if not msg:
            raise ValueError("Keine Nachricht empfangen")
        decrypted_msg = cipher.decrypt(msg).decode(FORMAT)  # Entschlüsseln
        print(decrypted_msg)
        return True, decrypted_msg
    except ConnectionError:
        print("[ERROR] Verbindung zum Server verloren")
        return False, None
    except Exception as e:
        print(f"[ERROR] Unerwarteter Fehler: {type(e).__name__}: {str(e)}")
        return False, None

def receive(boolean=True, times=0, cipher=None):
    if boolean:  # Endlosschleife für den Thread
        while True:
            success, msg = process_message(cipher)
            if not success:
                print("[ERROR] Verbindung verloren. Beende Client...")
                client.close()
                break
    else:  # Begrenzte Empfänge für Registrierung
        for i in range(times):
            success, msg = process_message(cipher)
            if not success:
                return False, None
            return True, msg  # Direkt msg zurückgeben

# DH Schlüsselaustausch für smooth brain 
param_bytes = client.recv(HEADER).decode(FORMAT).strip()
param_bytes = client.recv(int(param_bytes)).decode(FORMAT)
parameters = serialization.load_pem_parameters(param_bytes.encode(FORMAT))
server_public_bytes = client.recv(HEADER).decode(FORMAT).strip()
server_public_bytes = client.recv(int(server_public_bytes)).decode(FORMAT)
server_public_key = serialization.load_pem_public_key(server_public_bytes.encode(FORMAT))
private_key = parameters.generate_private_key()
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
send(public_bytes.decode(FORMAT))  # Sende öffentlichen Schlüssel ohne cipher
shared_key = private_key.exchange(server_public_key)
fernet_key = base64.urlsafe_b64encode(shared_key[:32])  # Fernet-Schlüssel
cipher = Fernet(fernet_key)

# Username-Eingabe
while username is None:
    print("Bitte wähle einen Benutzernamen:")
    username = input().strip()
    send(username, cipher)
    success, response = receive(False, 1, cipher)
    if not success:
        print("[ERROR] Verbindung verloren, Programm wird beendet.")
        client.close()
        exit()
    if response == BAD_NAME:
        username = None

# Empfangs-Thread starten
thread = threading.Thread(target=receive, args=(True, 0, cipher), daemon=True)
thread.start()

# Hauptschleife für Nachrichten
while True:
    msg = input().strip()
    if msg == DISCONNECT_MESSAGE:
        send(DISCONNECT_MESSAGE, cipher)
        break
    if msg == "SHOW" or msg.startswith("@"):
        send(msg, cipher)
    else:
        print("❌ Falsches Format! Nutze: @Benutzer Nachricht")

client.close()
print("Verbindung geschlossen.")