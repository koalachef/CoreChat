import socket
import threading 
import json

HEADER = 64
PORT = 5044
LOCAL_IP = socket.gethostbyname(socket.gethostname())
ADDR = (LOCAL_IP,PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
BAD_NAME = "Username is not Available"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Erstellt einen TCP-Server
server.bind(ADDR)
#Bindet TCP-Server an Lokale IP und PORT

clients = {}  # Dictionary: username -> conn

def codec(msg, a):#Codec ist eine Funktion für DE/EN-Coding
    return msg.encode(FORMAT) if a else msg.decode(FORMAT)

def sender(conn,msg):
    message = codec(msg,True)
    send_length = codec(str(len(message)),True)
    send_length += b" " * (HEADER - len(send_length))
    conn.send(send_length)
    conn.send(message)

def broadcast(msg):
    for conn in clients.values():
        try:
            sender(conn,msg)
        except:
            pass #falls ein fehler gibt temporär

def target(msg, target_username):
    if target_username in clients:
        try:
            sender(clients[target_username], msg)
        except:
            print(f"Fehler beim Senden an {target_username}")
    else:
        print(f"Benutzername {target_username} nicht vorhanden")
            
def server_input():
    while True:
        a = input().split(None, 1)

        if a[0] == "@show":
            count = 0
            for username in clients.keys():
                count += 1
                print(f"{count}: {username}")
        elif a[0][0] == "@" and a[0] != "@BC":
            if len(a) > 1:
                target_username = a[0][1:]
                target(a[1], target_username)
            else:
                print("Bitte eine Nachricht angeben!")
        elif a[0] == "@BC":
            if len(a) > 1:
                broadcast(a[1])
            else:
                print("Bitte eine Nachricht nach @BC angeben!")
        else:
            print("Folgende Befehle können genutzt werden:")
            print("@show : zeigt die Benutzernamen aller verbundenen Clients")
            print("@(Benutzername) : Nachricht an jeweiligen Client")
            print("@BC : Broadcast an alle Clients")

def receive_message(conn):
    try:
        msg_length = conn.recv(HEADER).decode(FORMAT).strip()
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            return msg
        return None
    except ConnectionError:
        return None
    except Exception as e:
        print(f"[ERROR] Empfangsfehler: {e}")
        return None

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    username = None
    try:
        # Username-Registrierung
        while True:
            username = receive_message(conn)
            if not username:  # Verbindung verloren oder Fehler
                conn.close()
                return
            
            if username in clients:
                sender(conn, BAD_NAME)  # Sende Ablehnung, aber halte Verbindung offen
                continue  # Warte auf neuen Versuch
            else:
                clients[username] = conn
                print(f"[USERNAME] {username} assigned to {addr}")
                sender(conn, f"Willkommen, {username}! Du kannst jetzt Nachrichten senden.")
                break  # Username akzeptiert, Schleife verlassen

        # Hauptschleife für Nachrichten
        while True:
            msg = receive_message(conn)
            if msg is None:
                break

            if msg == DISCONNECT_MESSAGE:
                break
            if msg == "SHOW":
                try:
                    for username in clients:
                        print(username)
                except Exception as e:
                    print(f"Fehler beim Anzeigen der Benutzer: {e}")
            elif msg.startswith("@"):
                parts = msg.split(" ", 1)
                if len(parts) > 1:
                    target_username = parts[0][1:]
                    target_msg = parts[1]
                    if target_username in clients:
                        target(f"[{username}] {target_msg}", target_username)
                        sender(conn, f"✅ Nachricht an {target_username} gesendet.")
                    else:
                        sender(conn, f"❌ Benutzer {target_username} existiert nicht.")
                else:
                    sender(conn, "❌ Nachricht fehlt!")
            else:
                sender(conn, "❌ Nachricht muss mit '@Benutzer Nachricht' beginnen.")

    except ConnectionError:
        print(f"[ERROR] Verbindung zu {addr} verloren")
    except Exception as e:
        print(f"[ERROR] Unerwarteter Fehler bei {addr}: {e}")
    finally:
        conn.close()
        if username and username in clients:
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
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

print("[STARTING] server is starting...")
start()