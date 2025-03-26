import socket
import threading 
import json
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import base64

HEADER = 64
PORT = 5044
LOCAL_IP = socket.gethostbyname(socket.gethostname())
ADDR = (LOCAL_IP,PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
BAD_NAME = "Username is not Available"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = {}  # Dictionary: username -> (conn, cipher)
parameters = dh.generate_parameters(generator=2, key_size=2048)

def codec(msg, a):
    return msg.encode(FORMAT) if a else msg.decode(FORMAT)

def sender(conn, msg, cipher=None):
    if cipher:
        message = cipher.encrypt(codec(msg, True))
        send_length = codec(str(len(message)), True)
        send_length += b" " * (HEADER - len(send_length))
        conn.send(send_length)
        conn.send(message)
    else:
        message = codec(msg, True)
        send_length = codec(str(len(message)), True)
        send_length += b" " * (HEADER - len(send_length))
        conn.send(send_length)
        conn.send(message)

def broadcast(msg, sender_cipher):
    for username, (conn, cipher) in clients.items():
        try:
            sender(conn, msg, cipher)  # Nutze den Cipher des Empfängers
        except:
            pass

def target(msg, target_username, sender_cipher):
    if target_username in clients:
        try:
            conn, cipher = clients[target_username]
            sender(conn, msg, cipher)  # Nutze den Cipher des Empfängers
        except:
            print(f"Fehler beim Senden an {target_username}")
    else:
        print(f"Benutzername {target_username} nicht vorhanden")

def server_input():
    while True:
        try:
            a = input().split(None, 1)
            if not a:
                print("Bitte was eingeben")
                continue
            elif a[0] == "@show":
                count = 0
                for username in clients.keys():
                    count += 1
                    print(f"{count}: {username}")
            elif a[0][0] == "@" and a[0] != "@BC":
                if len(a) > 1:
                    target_username = a[0][1:]
                    target(a[1], target_username, None)  # Kein Cipher für Server-Eingabe
                else:
                    print("Bitte eine Nachricht angeben!")
            elif a[0] == "@BC":
                if len(a) > 1:
                    broadcast(a[1], None)  # Kein Cipher für Server-Eingabe
                else:
                    print("Bitte eine Nachricht nach @BC angeben!")
            else:
                print("Folgende Befehle können genutzt werden:")
                print("@show : zeigt die Benutzernamen aller verbundenen Clients")
                print("@(Benutzername) : Nachricht an jeweiligen Client")
                print("@BC : Broadcast an alle Clients")
        except Exception as e:
            print(f"[ERROR] Ein Fehler ist aufgetreten: {e}")

def receive_message(conn, cipher=None):
    try:
        msg_length = conn.recv(HEADER).decode(FORMAT).strip()
        if not msg_length:
            return None
        msg_length = int(msg_length)
        msg = conn.recv(msg_length)
        if cipher:
            return cipher.decrypt(msg).decode(FORMAT)
        return msg.decode(FORMAT)
    except ConnectionError:
        return None
    except Exception as e:
        print(f"[ERROR] Empfangsfehler: {e}")
        return None

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    username = None

    # DH Schlüsselaustausch
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    param_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    sender(conn, param_bytes.decode(FORMAT))  # Sende DH-Parameter
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sender(conn, public_bytes.decode(FORMAT))  # Sende öffentlichen Schlüssel

    client_public_bytes = receive_message(conn)
    if not client_public_bytes:
        conn.close()
        return
    client_public_key = serialization.load_pem_public_key(client_public_bytes.encode(FORMAT))
    shared_key = private_key.exchange(client_public_key)
    fernet_key = base64.urlsafe_b64encode(shared_key[:32])
    cipher = Fernet(fernet_key)

    try:
        # Username-Registrierung
        while True:
            username = receive_message(conn, cipher)
            if not username:
                conn.close()
                return
            if username in clients:
                sender(conn, BAD_NAME, cipher)
                continue
            else:
                clients[username] = (conn, cipher)  # Speichere conn und cipher
                print(f"[USERNAME] {username} assigned to {addr}")
                sender(conn, f"Willkommen, {username}! Du kannst jetzt Nachrichten senden.", cipher)
                break

        # Hauptschleife für Nachrichten
        while True:
            msg = receive_message(conn, cipher)
            if msg is None:
                break
            if msg == DISCONNECT_MESSAGE:
                break
            if msg == "SHOW":
                try:
                    for user in clients:
                        print(user)
                except Exception as e:
                    print(f"Fehler beim Anzeigen der Benutzer: {e}")
            elif msg.startswith("@"):
                parts = msg.split(" ", 1)
                if len(parts) > 1:
                    target_username = parts[0][1:]
                    target_msg = parts[1]
                    if target_username in clients:
                        target(f"[{username}] {target_msg}", target_username, cipher)
                        sender(conn, f"✅ Nachricht an {target_username} gesendet.", cipher)
                    else:
                        sender(conn, f"❌ Benutzer {target_username} existiert nicht.", cipher)
                else:
                    sender(conn, "❌ Nachricht fehlt!", cipher)
            else:
                sender(conn, "❌ Nachricht muss mit '@Benutzer Nachricht' beginnen.", cipher)

    except ConnectionError:
        print(f"[ERROR] Verbindung zu {addr} verloren")
    except Exception as e:
        print(f"[ERROR] Unerwarteter Fehler bei {addr}: {e}")
    finally:
        conn.close()
        if username in clients:
            del clients[username]
        print(f"[DISCONNECTED] {addr} disconnected")

def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {LOCAL_IP}")
    threading.Thread(target=server_input, daemon=True).start()
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 2}")

print("[STARTING] server is starting...")
start()