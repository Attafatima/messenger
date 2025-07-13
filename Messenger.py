import sys
import os
import shutil
import socket
import threading
import sqlite3
import bcrypt
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, \
    QPushButton, QMessageBox, QFileDialog, QListWidget, QTextEdit, QStackedWidget, QListWidgetItem, QGridLayout, QDialog
from PyQt6.QtGui import QPixmap, QIcon
from PyQt6.QtCore import Qt, pyqtSignal, QObject

# Constants
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) #finds the folder messenger.py on computer
DB_PATH = os.path.join(BASE_DIR, 'messenger.db') #creates full database path by combining base_dir with messenger.db
#all user accounts and messages will be stored in the above (db_path)
DEFAULT_AVATAR = os.path.join(BASE_DIR, 'C:/Users/ALPHA/OneDrive/Desktop/Wallpapers')


#Create the database
def create_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    #Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        phone_number TEXT UNIQUE,
        password TEXT NOT NULL,
        profile_pic TEXT,
        bio TEXT
    )
    ''')

    #Contacts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS contacts (
        user_id INTEGER NOT NULL,
        contact_id INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(contact_id) REFERENCES users(id),
        PRIMARY KEY(user_id, contact_id)
    )
    ''')

    #Messages table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_file BOOLEAN DEFAULT 0,
        file_path TEXT,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )
    ''')
    conn.commit() #commit the connection
    conn.close() #close the connection
create_db()


#Signal class for cross-thread communication
class Communicate(QObject):
    new_message = pyqtSignal(str, str)  #first str for message, second for the sender


#Server Thread - This creates a new thread (parallel task) that runs a chat server.
# it also lets the app handle many users simultaneously without freezing
class ServerThread(threading.Thread):
    def __init__(self, port=12345):
        super().__init__()
        self.port = port #stores the port number for later usage
        self.running = True #creates like a flag to control the thread's on/off switch
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates TCP/IP socket to ensure messages arrive in order and are intact
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #allows reusing of the port immediately after restarting, to address any 'already in use' errors
        self.server_socket.bind(('localhost', self.port)) #this binds the socket to 'localhost' and the specified port (literally telling the OS to send all messages for that port to me)
        self.server_socket.listen(5) #this allows up to 5 pending connections in queue to handle brief connection surges without dropping users
        self.clients = {} #creates a dictionary to track connected users so we know who is online and where to send their messages

    def run(self): #the code that runs when the thread starts
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept() #waits for a user to connect. It's how the server detects new users
                threading.Thread(target=self.handle_client, args=(client_socket,)).start() #starts a new thread for each connected user and lets the server chat with more than one user at once
            except:
                break

    def handle_client(self, client_socket): #manages communication with one connected user so that each user gets their own special handler
        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8')
                if not data: #if the connection was closed so users don't disconnect unexpectedly
                    break

                #splitting messages into different sections to route messages to the correct recipient
                parts = data.split(':', 2)
                if len(parts) == 3:
                    sender_id, receiver_id, message = parts
                    self.broadcast_message(sender_id, receiver_id, message)
        finally:
            client_socket.close()

    def broadcast_message(self, sender_id, receiver_id, message): #this helps to send a message to the intended recipient
        #save to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, content)
        VALUES (?, ?, ?)
        ''', (sender_id, receiver_id, message))
        conn.commit()
        conn.close()

        #forward to the recipient if connected
        if receiver_id in self.clients:
            self.clients[receiver_id].send(f"{sender_id}:{message}".encode('utf-8'))

    def stop(self):
        self.running = False
        self.server_socket.close()


#Client Socket Handler - This creates a client that connects to the server to send/receive messages
class ClientSocket:
    def __init__(self, user_id, port=12345):
        self.user_id = user_id
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(('localhost', self.port))
        self.running = True

    def send_message(self, receiver_id, message):
        data = f"{self.user_id}:{receiver_id}:{message}" #formats the message so the server knows who sends and who receives messages
        self.socket.send(data.encode('utf-8'))

    def receive_messages(self, callback): #checks for incoming messages
        while self.running:
            try:
                data = self.socket.recv(1024).decode('utf-8')
                if data:
                    parts = data.split(':', 1)
                    if len(parts) == 2:
                        sender_id, message = parts
                        callback(sender_id, message)
            except:
                break

    def close(self): #Stops checking and disconnects from the server
        self.running = False
        self.socket.close()


#GUI Application
class MessengerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_user = None
        self.client_socket = None
        self.server_thread = None
        self.setWindowTitle("Messenger App")
        self.setWindowIcon(QIcon('logo.jpg'))
        self.setGeometry(100, 100, 800, 600)

        #Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        #Create screens
        self.login_screen = self.create_login_screen()
        self.signup_screen = self.create_signup_screen()
        self.main_screen = self.create_main_screen()
        self.profile_screen = self.create_profile_screen()
        self.add_contact_screen = self.create_add_contact_screen()
        self.chat_screen = self.create_chat_screen()
        self.settings_screen = self.create_settings_screen()

        #Add screens to stacked widget
        self.stacked_widget.addWidget(self.login_screen)
        self.stacked_widget.addWidget(self.signup_screen)
        self.stacked_widget.addWidget(self.main_screen)
        self.stacked_widget.addWidget(self.profile_screen)
        self.stacked_widget.addWidget(self.add_contact_screen)
        self.stacked_widget.addWidget(self.chat_screen)
        self.stacked_widget.addWidget(self.settings_screen)

        #Start server thread
        self.start_server()

        #Show login screen first
        self.stacked_widget.setCurrentWidget(self.login_screen)

    def start_server(self):
        self.server_thread = ServerThread()
        self.server_thread.start()

    def stop_server(self):
        if self.server_thread:
            self.server_thread.stop()
            self.server_thread.join()

    def closeEvent(self, event):
        self.stop_server()
        if self.client_socket:
            self.client_socket.close()
        event.accept()

    #Screen creation methods
    def create_login_screen(self):
        widget = QWidget()

        background = QLabel(widget)
        pixmap = QPixmap("Intro.jpg")
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)

        layout = QVBoxLayout()

        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Username")
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Password")
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)

        login_btn = QPushButton("Sign In")
        login_btn.clicked.connect(self.handle_login)

        signup_btn = QPushButton("Go to Sign Up")
        signup_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.signup_screen))

        layout.addWidget(QLabel("Sign In"))
        layout.addWidget(self.login_username)
        layout.addWidget(self.login_password)
        layout.addWidget(login_btn)
        layout.addWidget(signup_btn)

        widget.setLayout(layout)
        return widget

    def create_signup_screen(self):
        widget = QWidget()
        layout = QVBoxLayout()

        self.signup_username = QLineEdit()
        self.signup_username.setPlaceholderText("Username")
        self.signup_phone = QLineEdit()
        self.signup_phone.setPlaceholderText("Phone Number")
        self.signup_password = QLineEdit()
        self.signup_password.setPlaceholderText("Password")
        self.signup_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.signup_confirm_password = QLineEdit()
        self.signup_confirm_password.setPlaceholderText("Confirm Password")
        self.signup_confirm_password.setEchoMode(QLineEdit.EchoMode.Password)

        signup_btn = QPushButton("Sign Up")
        signup_btn.clicked.connect(self.handle_signup)

        login_btn = QPushButton("Go to Sign In")
        login_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.login_screen))

        layout.addWidget(QLabel("Sign Up"))
        layout.addWidget(self.signup_username)
        layout.addWidget(self.signup_phone)
        layout.addWidget(self.signup_password)
        layout.addWidget(self.signup_confirm_password)
        layout.addWidget(signup_btn)
        layout.addWidget(login_btn)

        widget.setLayout(layout)
        return widget

    def create_main_screen(self):
        widget = QWidget()
        layout = QHBoxLayout()

        #Left sidebar
        sidebar = QVBoxLayout()

        #User profile at top
        self.user_profile_btn = QPushButton()
        self.user_profile_btn.setIcon(QIcon(DEFAULT_AVATAR))
        self.user_profile_btn.setIconSize(QPixmap(DEFAULT_AVATAR).size())
        self.user_profile_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.profile_screen))
        sidebar.addWidget(self.user_profile_btn)

        #Contacts list
        self.contacts_list = QListWidget()
        self.contacts_list.itemClicked.connect(self.open_chat)
        sidebar.addWidget(QLabel("Contacts"))
        sidebar.addWidget(self.contacts_list)

        #Add contact button
        add_contact_btn = QPushButton("Add Contact")
        add_contact_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.add_contact_screen))
        sidebar.addWidget(add_contact_btn)

        #Settings button
        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.settings_screen))
        sidebar.addWidget(settings_btn)

        #Right side (empty initially)
        self.main_right = QWidget()

        layout.addLayout(sidebar, 1)
        layout.addWidget(self.main_right, 3)

        widget.setLayout(layout)
        return widget

    def create_profile_screen(self):
        widget = QWidget()
        layout = QVBoxLayout()

        #Profile picture
        self.profile_pic_label = QLabel()
        self.profile_pic_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.profile_pic_btn = QPushButton("Change Profile Picture")
        self.profile_pic_btn.clicked.connect(self.change_profile_pic)

        #User info
        self.profile_username = QLineEdit()
        self.profile_phone = QLineEdit()
        self.profile_bio = QTextEdit()
        self.profile_bio.setPlaceholderText("Enter your bio here...")

        #Save button
        save_btn = QPushButton("Save Changes")
        save_btn.clicked.connect(self.save_profile_changes)

        #Back button
        back_btn = QPushButton("Back")
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.main_screen))

        layout.addWidget(self.profile_pic_label)
        layout.addWidget(self.profile_pic_btn)
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.profile_username)
        layout.addWidget(QLabel("Phone:"))
        layout.addWidget(self.profile_phone)
        layout.addWidget(QLabel("Bio:"))
        layout.addWidget(self.profile_bio)
        layout.addWidget(save_btn)
        layout.addWidget(back_btn)

        widget.setLayout(layout)
        return widget

    def create_add_contact_screen(self):
        widget = QWidget()
        background = QLabel(widget)
        pixmap = QPixmap("back3.jpg")
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)
        layout = QVBoxLayout()

        self.add_contact_username = QLineEdit()
        self.add_contact_username.setPlaceholderText("Username or Phone Number")

        add_btn = QPushButton("Add Contact")
        add_btn.clicked.connect(self.add_contact)

        back_btn = QPushButton("Back")
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.main_screen))

        layout.addWidget(QLabel("Add Contact"))
        layout.addWidget(self.add_contact_username)
        layout.addWidget(add_btn)
        layout.addWidget(back_btn)

        widget.setLayout(layout)
        return widget

    def create_chat_screen(self):
        widget = QWidget()
        background = QLabel(widget)
        pixmap = QPixmap("back3.jpg")
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)

        layout = QVBoxLayout()

        #Chat header (with back button and contact name)
        header = QHBoxLayout()
        back_btn = QPushButton("Back")
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.main_screen))
        self.chat_contact_name = QLabel()
        header.addWidget(back_btn)
        header.addWidget(self.chat_contact_name)
        header.addStretch()

        #Chat messages display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)

        #Message input area
        message_input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_chat_message)

        #File transfer button
        file_btn = QPushButton("Send File")
        file_btn.clicked.connect(self.send_file)

        message_input_layout.addWidget(self.message_input, 4)
        message_input_layout.addWidget(send_btn, 1)
        message_input_layout.addWidget(file_btn, 1)

        #Stickers button
        stickers_btn = QPushButton("Stickers")
        stickers_btn.clicked.connect(self.show_stickers)

        layout.addLayout(header)
        layout.addWidget(self.chat_display)
        layout.addLayout(message_input_layout)
        layout.addWidget(stickers_btn)

        widget.setLayout(layout)
        return widget

    def create_settings_screen(self):
        widget = QWidget()
        layout = QVBoxLayout()

        #Changing the password
        self.current_password = QLineEdit()
        self.current_password.setPlaceholderText("Current Password")
        self.current_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password = QLineEdit()
        self.new_password.setPlaceholderText("New Password")
        self.new_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_new_password = QLineEdit()
        self.confirm_new_password.setPlaceholderText("Confirm New Password")
        self.confirm_new_password.setEchoMode(QLineEdit.EchoMode.Password)

        change_pwd_btn = QPushButton("Change Password")
        change_pwd_btn.clicked.connect(self.change_password)

        #Back button
        back_btn = QPushButton("Back")
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.main_screen))

        layout.addWidget(QLabel("Change Password"))
        layout.addWidget(self.current_password)
        layout.addWidget(self.new_password)
        layout.addWidget(self.confirm_new_password)
        layout.addWidget(change_pwd_btn)
        layout.addWidget(back_btn)

        widget.setLayout(layout)
        return widget

    #Database helper functiions
    def get_user_by_username(self, username):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        return user

    def get_user_by_phone(self, phone):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE phone_number = ?", (phone,))
        user = cursor.fetchone()
        conn.close()
        return user

    def get_user_by_id(self, user_id):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user

    def get_contacts(self, user_id):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT u.id, u.username, u.profile_pic 
        FROM users u JOIN contacts c ON u.id = c.contact_id 
        WHERE c.user_id = ?
        ''', (user_id,))
        contacts = cursor.fetchall()
        conn.close()
        return contacts

    def get_messages(self, user1_id, user2_id):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT * FROM messages 
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp
        ''', (user1_id, user2_id, user2_id, user1_id))
        messages = cursor.fetchall()
        conn.close()
        return messages

    #Authentication methods
    def handle_login(self):
        username = self.login_username.text()
        password = self.login_password.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter both username and password")
            return

        user = self.get_user_by_username(username)
        if not user:
            QMessageBox.warning(self, "Error", "User not found")
            return

        if bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            self.current_user = {
                'id': user[0],
                'username': user[1],
                'phone': user[2],
                'profile_pic': user[4],
                'bio': user[5]
            }

            #Update UI with user data
            self.update_main_screen()

            #Connect to socket server
            self.client_socket = ClientSocket(self.current_user['id'])
            threading.Thread(
                target=self.client_socket.receive_messages,
                args=(self.handle_received_message,),
                daemon=True
            ).start()

            self.stacked_widget.setCurrentWidget(self.main_screen)
        else:
            QMessageBox.warning(self, "Error", "Incorrect password")

    def handle_signup(self):
        username = self.signup_username.text()
        phone = self.signup_phone.text()
        password = self.signup_password.text()
        confirm_password = self.signup_confirm_password.text()

        #Validation
        if not username or not password or not confirm_password:
            QMessageBox.warning(self, "Error", "Please fill all required fields")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return

        if self.get_user_by_username(username):
            QMessageBox.warning(self, "Error", "Username already exists")
            return

        if phone and self.get_user_by_phone(phone):
            QMessageBox.warning(self, "Error", "Phone number already in use")
            return

        #Hash password
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        #Save to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute('''
            INSERT INTO users (username, phone_number, password, profile_pic)
            VALUES (?, ?, ?, ?)
            ''', (username, phone, hashed_pw, DEFAULT_AVATAR))
            conn.commit()
            QMessageBox.information(self, "Success", "Account created successfully!")
            self.stacked_widget.setCurrentWidget(self.login_screen)
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {e}")
        finally:
            conn.close()

    #Profile methods
    def update_main_screen(self):
        #Update profile button
        if self.current_user['profile_pic']:
            self.user_profile_btn.setIcon(QIcon(self.current_user['profile_pic']))
            self.user_profile_btn.setIconSize(QPixmap(self.current_user['profile_pic']).size())
        else:
            self.user_profile_btn.setIcon(QIcon(DEFAULT_AVATAR))
            self.user_profile_btn.setIconSize(QPixmap(DEFAULT_AVATAR).size())

        #Update contacts list
        self.contacts_list.clear()
        contacts = self.get_contacts(self.current_user['id'])
        for contact in contacts:
            item = QListWidgetItem(contact[1])
            item.setData(Qt.ItemDataRole.UserRole, contact[0])  # Store user_id
            self.contacts_list.addItem(item)

    def open_chat(self, item):
        contact_id = item.data(Qt.ItemDataRole.UserRole)
        contact = self.get_user_by_id(contact_id)

        if not contact:
            QMessageBox.warning(self, "Error", "Contact not found")
            return

        self.current_chat = {
            'id': contact[0],
            'name': contact[1]
        }

        self.chat_contact_name.setText(f"Chat with {contact[1]}")
        self.load_chat_messages()
        self.stacked_widget.setCurrentWidget(self.chat_screen)

    def load_chat_messages(self):
        self.chat_display.clear()
        messages = self.get_messages(self.current_user['id'], self.current_chat['id'])

        for msg in messages:
            sender_id, content = msg[1], msg[3]
            if sender_id == self.current_user['id']:
                # Message from current user (right aligned)
                self.chat_display.append(f"<div style='text-align:right; color:blue;'>You: {content}</div>")
            else:
                # Message from contact (left aligned)
                self.chat_display.append(
                    f"<div style='text-align:left; color:green;'>{self.current_chat['name']}: {content}</div>")

    def send_chat_message(self):
        message = self.message_input.text()
        if not message:
            return

        #Send via socket
        self.client_socket.send_message(self.current_chat['id'], message)

        #Update UI
        self.chat_display.append(f"<div style='text-align:right; color:blue;'>You: {message}</div>")
        self.message_input.clear()

    def handle_received_message(self, sender_id, message):
        #Check if this message is from the currently open chat
        if hasattr(self, 'current_chat') and str(self.current_chat['id']) == sender_id:
            sender = self.get_user_by_id(int(sender_id))
            if sender:
                self.chat_display.append(f"<div style='text-align:left; color:green;'>{sender[1]}: {message}</div>")

    def change_profile_pic(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Profile Picture", "",
            "Image Files (*.png *.jpg *.jpeg)"
        )

        if file_path:
            try:
                #Create a profile_pictures directory if it doesn't exist
                pics_dir = os.path.join(BASE_DIR, 'profile_pictures')
                os.makedirs(pics_dir, exist_ok=True)

                #Save to user-specific file
                dest = os.path.join(pics_dir, f"user_{self.current_user['id']}.jpg")
                shutil.copy(file_path, dest)

                #Update database
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE users SET profile_pic = ? WHERE id = ?
                ''', (dest, self.current_user['id']))
                conn.commit()
                conn.close()

                #Update current user data
                self.current_user['profile_pic'] = dest

                #Update UI
                self.profile_pic_label.setPixmap(QPixmap(dest).scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
                self.update_main_screen()

                QMessageBox.information(self, "Success", "Profile picture updated!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not update picture: {e}")

    def save_profile_changes(self):
        new_username = self.profile_username.text()
        new_phone = self.profile_phone.text()
        new_bio = self.profile_bio.toPlainText()

        #Validate username uniqueness
        if new_username != self.current_user['username']:
            if self.get_user_by_username(new_username):
                QMessageBox.warning(self, "Error", "Username already taken")
                return

        #Validate phone uniqueness
        if new_phone != self.current_user['phone']:
            if new_phone and self.get_user_by_phone(new_phone):
                QMessageBox.warning(self, "Error", "Phone number already in use")
                return

        #Update database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute('''
            UPDATE users 
            SET username = ?, phone_number = ?, bio = ?
            WHERE id = ?
            ''', (new_username, new_phone, new_bio, self.current_user['id']))
            conn.commit()

            #Update current user data
            self.current_user['username'] = new_username
            self.current_user['phone'] = new_phone
            self.current_user['bio'] = new_bio

            QMessageBox.information(self, "Success", "Profile updated successfully!")
            self.update_main_screen()
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {e}")
        finally:
            conn.close()

    def add_contact(self):
        username_or_phone = self.add_contact_username.text()
        if not username_or_phone:
            QMessageBox.warning(self, "Error", "Please enter a username or phone number")
            return

        #Check if contact exists
        contact = None
        if username_or_phone.isdigit():
            contact = self.get_user_by_phone(username_or_phone)
        else:
            contact = self.get_user_by_username(username_or_phone)

        if not contact:
            QMessageBox.warning(self, "Error", "User not found")
            return

        if contact[0] == self.current_user['id']:
            QMessageBox.warning(self, "Error", "You cannot add yourself")
            return

        #Check if already a contact
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT 1 FROM contacts 
        WHERE user_id = ? AND contact_id = ?
        ''', (self.current_user['id'], contact[0]))
        if cursor.fetchone():
            QMessageBox.warning(self, "Error", "This user is already in your contacts")
            conn.close()
            return

        #Add contact
        try:
            cursor.execute('''
            INSERT INTO contacts (user_id, contact_id)
            VALUES (?, ?)
            ''', (self.current_user['id'], contact[0]))
            conn.commit()
            QMessageBox.information(self, "Success", "Contact added successfully!")
            self.update_main_screen()
            self.stacked_widget.setCurrentWidget(self.main_screen)
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {e}")
        finally:
            conn.close()

    def change_password(self):
        current_pw = self.current_password.text()
        new_pw = self.new_password.text()
        confirm_pw = self.confirm_new_password.text()

        if not current_pw or not new_pw or not confirm_pw:
            QMessageBox.warning(self, "Error", "Please fill all fields")
            return

        if new_pw != confirm_pw:
            QMessageBox.warning(self, "Error", "New passwords don't match")
            return

        #Verify current password
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id = ?", (self.current_user['id'],))
        db_pw = cursor.fetchone()[0]

        if not bcrypt.checkpw(current_pw.encode('utf-8'), db_pw.encode('utf-8')):
            QMessageBox.warning(self, "Error", "Current password is incorrect")
            conn.close()
            return

        #Update password
        hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            cursor.execute('''
            UPDATE users SET password = ? WHERE id = ?
            ''', (hashed_pw, self.current_user['id']))
            conn.commit()
            QMessageBox.information(self, "Success", "Password changed successfully!")
            self.current_password.clear()
            self.new_password.clear()
            self.confirm_new_password.clear()
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Error", f"Database error: {e}")
        finally:
            conn.close()

    def send_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Send", "",
            "All Files (*);;PDF (*.pdf);;Images (*.png *.jpg *.jpeg)"
        )

        if file_path:
            try:
                filename = os.path.basename(file_path)
                self.client_socket.send_message(
                    self.current_chat['id'],
                    f"[FILE] {filename}"
                )
                self.chat_display.append(
                    f"<div style='text-align:right; color:blue;'>You sent file: {filename}</div>"
                )
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not send file: {e}")

    def show_stickers(self):
        stickers = ["😀", "😂", "😍", "👍", "❤️", "🔥", "🎉", "🤔"]

        sticker_dialog = QDialog(self)
        sticker_dialog.setWindowTitle("Select Sticker")
        layout = QGridLayout()

        for i, sticker in enumerate(stickers):
            btn = QPushButton(sticker)
            btn.setFont(btn.font().defaultFamily(), 24)
            btn.clicked.connect(lambda _, s=sticker: self.send_sticker(s, sticker_dialog))
            layout.addWidget(btn, i // 4, i % 4)

        sticker_dialog.setLayout(layout)
        sticker_dialog.exec()

    def send_sticker(self, sticker, dialog):
        self.client_socket.send_message(self.current_chat['id'], sticker)
        self.chat_display.append(
            f"<div style='text-align:right; color:blue;'>You: {sticker}</div>"
        )
        dialog.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    #Create default avatar if it doesn't exist
    if not os.path.exists(DEFAULT_AVATAR):
        from PyQt6.QtGui import QPainter, QColor

        pixmap = QPixmap(200, 200)
        pixmap.fill(QColor(200, 200, 200))
        painter = QPainter(pixmap)
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "No Photo")
        painter.end()
        pixmap.save(DEFAULT_AVATAR)

    window = MessengerApp()
    window.show()
    sys.exit(app.exec())