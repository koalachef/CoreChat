import socket
import threading

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

def send(msg):
    message = codec(msg, True)
    send_length = codec(str(len(message)), True)
    send_length += b" " * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)

def process_message():
    try:
        msg_length = client.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = client.recv(msg_length).decode(FORMAT)
            print(msg)
            return True, msg
    except ConnectionError:
        print("[ERROR] Verbindung zum Server verloren")
        return False, None
    except Exception as e:
        print(f"[ERROR] Unerwarteter Fehler: {e}")
        return False, None

def receive(boolean=True, times=0):
    last_msg = None
    while boolean:
        success, msg = process_message()
        if not success:
            return False, last_msg
        last_msg = msg
    for i in range(times):
        success, msg = process_message()
        if not success:
            return False, last_msg
        last_msg = msg
    return True, last_msg

# Username-Eingabe
while username is None:
    print("Bitte wähle einen Benutzernamen:")
    username = input().strip()
    send(username)
    success, response = receive(False, 1)
    if not success:
        print("[ERROR] Verbindung verloren, Programm wird beendet.")
        client.close()
        exit()
    if response == BAD_NAME:
        username = None

# Empfangs-Thread starten
thread = threading.Thread(target=receive, daemon=True)
thread.start()

# Hauptschleife für Nachrichten
while True:
    msg = input().strip()
    if msg == DISCONNECT_MESSAGE:
        send(DISCONNECT_MESSAGE)
        break
    if msg == "SHOW" or msg.startswith("@"):
        send(msg)
    else:
        print("❌ Falsches Format! Nutze: @Benutzer Nachricht")

client.close()
print("Verbindung geschlossen.")