import sys
import os
import shutil
import socket
import threading
import sqlite3
import bcrypt
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, \
    QPushButton, QMessageBox, QFileDialog, QListWidget, QTextEdit, QStackedWidget, QListWidgetItem, QGridLayout, QDialog
from PyQt6.QtGui import QPixmap, QIcon, QFont
from PyQt6.QtCore import Qt, pyqtSignal, QObject

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) #finds the folder messenger.py on computer
DB_PATH = os.path.join(BASE_DIR, 'messenger.db') #creates full database path by combining base_dir with messenger.db
#all user accounts and messages will be stored in the above (db_path)
DEFAULT_AVATAR = os.path.join(BASE_DIR, 'default_avatar.png') #sets the path for a default profile picture

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
                data = client_socket.recv(1024).decode('utf-8') #receives data/ messages from this user, max = 1024 bytes at a time to receive chat messages or commands
                if not data: #if the connection was closed so users don't disconnect unexpectedly
                    break

                #splitting messages into different sections to route messages to the correct recipient
                parts = data.split(':', 2) #format: "sender_id:receiver_id:message". 2 is the maximum splits to perform between the sender and receiver id
                if len(parts) == 3:
                    sender_id, receiver_id, message = parts
                    self.broadcast_message(sender_id, receiver_id, message)
        finally:
            client_socket.close() #closes the connection neatly when done to prevent resource leaks

    def broadcast_message(self, sender_id, receiver_id, message): #this helps to send a message to the intended recipient
        #save messages to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, content)
        VALUES (?, ?, ?)
        ''', (sender_id, receiver_id, message))
        conn.commit()
        conn.close()

        #if the recipient is online, this will help to send the message immediately
        if receiver_id in self.clients:
            self.clients[receiver_id].send(f"{sender_id}:{message}".encode('utf-8'))

    def stop(self): #safely shuts down the server
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
        self.socket.send(data.encode('utf-8')) #sends the message over the socket. Those messages must be encoded as bytes for the network

    def receive_messages(self, callback): #checks for incoming messages
        while self.running: #keeps waiting until we stop the client. So that the client doesn't quit after one message
            try:
                data = self.socket.recv(1024).decode('utf-8') #waits for a message. recv pauses while waiting for a text reply
                #splits the message into sender:content and calls the message_handler
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
        super().__init__() #calling the parent QMainWindow's constructor
        self.current_user = None
        self.client_socket = None #client socket network connection
        self.server_thread = None #background server
        self.setWindowTitle("Messenger App")
        self.setWindowIcon(QIcon('logo.jpg'))
        self.setGeometry(100, 100, 800, 600)

        #Create stacked widget for different screens - allows switching between screens
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

        #Add screens to stacked widget to make them available for later use
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
        self.server_thread.start() #calling ServerThread class to start server thread

    def stop_server(self): #To safely terminate the background server thread when the app closes
        if self.server_thread: #if server exists
            self.server_thread.running = False #signal the thread to stop
            self.server_thread.server_socket.close() #closes the socket
            self.server_thread.join() #wait for thread to finish

    # helps to close the messenger app window and ensures everything shuts down properly
    def closeEvent(self, event):
        self.stop_server()
        if self.client_socket: #if client_socket for logged in users exists
            self.client_socket.close()
        event.accept() #finishes the closing process

    #creating and configuring the login interface that users first see when opening the app
    def create_login_screen(self):
        widget = QWidget()
        widget.setFixedSize(800, 600)

        background = QLabel(widget)
        pixmap = QPixmap("Intro.jpg").scaled(800, 600) #.scaled here is to resize the image to ensure it fits the screen perfectly
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)

        font = QFont()
        font.setPointSize(18)
        font.setBold(True)

        sign_in = QLabel("Sign In", widget)
        sign_in.move(350, 150)
        sign_in.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sign_in.setFont(font)

        palette = sign_in.palette()
        palette.setColor(sign_in.foregroundRole(), Qt.GlobalColor.white)
        sign_in.setPalette(palette)

        layout = QVBoxLayout() #setting a vertical box layout

        #creating username and password
        self.login_username = QLineEdit(background)
        self.login_username.setPlaceholderText("Username")
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Password")
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)

        #creating sign in button
        login_btn = QPushButton("Sign In")
        login_btn.clicked.connect(self.handle_login) #once clicked, connects it to the login

        #creating sign up button
        signup_btn = QPushButton("Go to Sign Up")
        signup_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.signup_screen)) #when button clicked, switch the app from login to signup screen

        #arranges all elements vertically
        layout.addWidget(sign_in)
        layout.addWidget(self.login_username)
        layout.addWidget(self.login_password)
        layout.addWidget(login_btn)
        layout.addWidget(signup_btn)

        widget.setLayout(layout)
        return widget

    #handles signing up.. where users can create accounts
    def create_signup_screen(self):
        widget = QWidget()
        widget.setFixedSize(800, 600)

        background = QLabel(widget)
        pixmap = QPixmap("Intro.jpg").scaled(800, 600)  #.scaled here is to resize the image to ensure it fits the screen perfectly
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)
        layout = QVBoxLayout()

        font = QFont()
        font.setPointSize(18)
        font.setBold(True)

        sign_up = QLabel("Sign Up", widget)
        sign_up.move(350, 150)
        sign_up.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sign_up.setFont(font)

        palette = sign_up.palette()
        palette.setColor(sign_up.foregroundRole(), Qt.GlobalColor.white)
        sign_up.setPalette(palette)

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

        layout.addWidget(sign_up)
        layout.addWidget(self.signup_username)
        layout.addWidget(self.signup_phone)
        layout.addWidget(self.signup_password)
        layout.addWidget(self.signup_confirm_password)
        layout.addWidget(signup_btn)
        layout.addWidget(login_btn)

        widget.setLayout(layout)
        return widget

    def create_main_screen(self): #handling the home base.. what users see after logging in
        widget = QWidget()
        widget.setFixedSize(800, 600)

        background = QLabel(widget)
        pixmap = QPixmap("back3.jpg").scaled(800, 600)
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)

        nav_panel = QLabel("Navigation Panel", widget)
        nav_panel.setGeometry(800 - 20, 0, 200, 30)
        nav_panel.setAlignment(Qt.AlignmentFlag.AlignRight)

        font = QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(14)
        font.setBold(True)
        nav_panel.setFont(font)

        palette = nav_panel.palette()
        palette.setColor(nav_panel.foregroundRole(), Qt.GlobalColor.white)
        nav_panel.setPalette(palette)

        layout = QHBoxLayout()

        #Left sidebar - navigation panel
        sidebar = QVBoxLayout()
        sidebar.setContentsMargins(10, 20, 10, 10)
        sidebar.setSpacing(15)

        #User profile at the top
        self.user_profile_btn = QPushButton()
        self.user_profile_btn.setIcon(QIcon(DEFAULT_AVATAR))
        self.user_profile_btn.setGeometry(50, 20, 100, 100)
        self.user_profile_btn.setIconSize(QPixmap(DEFAULT_AVATAR).size())
        #self.user_profile_btn.setIconSize(QPixmap(DEFAULT_AVATAR).size())

        self.user_profile_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.profile_screen))
        sidebar.addWidget(self.user_profile_btn)

        #Contacts list
        self.contacts_list = QListWidget(widget)
        self.contacts_list.setGeometry(50, 100, 200, 300)
        self.contacts_list.itemClicked.connect(self.open_chat)
        sidebar.addWidget(QLabel("CONTACTS"))
        sidebar.addWidget(self.contacts_list)

        #Add contact button
        add_contact_btn = QPushButton("Add Contact")
        add_contact_btn.setGeometry(50, 470, 200, 30)
        add_contact_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.add_contact_screen))
        sidebar.addWidget(add_contact_btn)

        #Settings button
        settings_btn = QPushButton("Settings")
        settings_btn.setGeometry(50, 510, 200, 30)
        settings_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.settings_screen))
        sidebar.addWidget(settings_btn)

        #Right side (empty initially)
        self.main_right = QWidget()

        layout.addLayout(sidebar, 1)
        layout.addWidget(self.main_right, 3)
        layout.addWidget(nav_panel)
        widget.setLayout(layout)
        return widget

    def create_profile_screen(self): #creates the user profile screen where users can edit and view their profile information
        widget = QWidget()
        background = QLabel(widget)
        pixmap = QPixmap("back4.jpg").scaled(800, 600)
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)

        layout = QVBoxLayout()

        #Profile picture
        self.profile_pic_label = QLabel() #displays the profile picture
        self.profile_pic_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.profile_pic_btn = QPushButton("Change Profile Picture")
        self.profile_pic_btn.clicked.connect(self.change_profile_pic)

        #User info
        self.profile_username = QLineEdit()
        self.profile_username.setPlaceholderText("Username")
        self.profile_phone = QLineEdit()
        self.profile_phone.setPlaceholderText("Phone")
        self.profile_bio = QTextEdit()
        self.profile_bio.setPlaceholderText("Enter your bio here...")

        #Save button
        save_btn = QPushButton("Save Changes")
        save_btn.clicked.connect(self.save_profile_changes)

        #Back button
        back_btn = QPushButton("Back")
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.main_screen)) #returns to the main screen

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

        widget.setLayout(layout) #add layout to widget
        return widget

    def create_add_contact_screen(self): #create screen where users could add new contacts
        widget = QWidget()
        background = QLabel(widget)
        pixmap = QPixmap("back2.jpg").scaled(800, 600)
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)
        layout = QVBoxLayout()

        self.add_contact_username = QLineEdit()
        self.add_contact_username.setPlaceholderText("Username or Phone Number")

        add_btn = QPushButton("Add Contact")
        add_btn.clicked.connect(self.add_contact)

        back_btn = QPushButton("Back")
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.main_screen))

        font = QFont()
        font.setPointSize(18)
        font.setBold(True)

        add_contact = QLabel("Add Contact", widget)
        add_contact.move(350, 150)
        add_contact.setAlignment(Qt.AlignmentFlag.AlignCenter)
        add_contact.setFont(font)

        palette = add_contact.palette()
        palette.setColor(add_contact.foregroundRole(), Qt.GlobalColor.white)
        add_contact.setPalette(palette)
        layout.addWidget(add_contact)
        layout.addWidget(self.add_contact_username)
        layout.addWidget(add_btn)
        layout.addWidget(back_btn)

        widget.setLayout(layout)
        return widget

    def create_chat_screen(self): #create main chat interface
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
        self.chat_contact_name = QLabel() #displays the name of the current chat contact
        header.addWidget(back_btn)
        header.addWidget(self.chat_contact_name)
        header.addStretch()

        #Chat messages display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True) #making the chat display read only, no editing allowed

        #Message input area
        message_input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_chat_message)

        #File transfer button
        file_btn = QPushButton("Send File")
        file_btn.clicked.connect(self.send_file)

        message_input_layout.addWidget(self.message_input, 4) #it takes up to 4x more space than the widgets with 1
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

    def create_settings_screen(self): #create a screen where users can change password
        widget = QWidget()
        widget.setFixedSize(800, 600)

        background = QLabel(widget)
        pixmap = QPixmap("back5.jpg").scaled(800, 600)  # .scaled here is to resize the image to ensure it fits the screen perfectly
        background.setPixmap(pixmap)
        background.setGeometry(0, 0, 800, 600)
        layout = QVBoxLayout()

        font = QFont()
        font.setPointSize(18)
        font.setBold(True)

        passw = QLabel("Password Change", widget)
        passw.move(350, 150)
        passw.setAlignment(Qt.AlignmentFlag.AlignCenter)
        passw.setFont(font)

        palette = passw.palette()
        palette.setColor(passw.foregroundRole(), Qt.GlobalColor.white)
        passw.setPalette(palette)

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

        layout.addWidget(passw)
        layout.addWidget(self.current_password)
        layout.addWidget(self.new_password)
        layout.addWidget(self.confirm_new_password)
        layout.addWidget(change_pwd_btn)
        layout.addWidget(back_btn)

        widget.setLayout(layout)
        return widget

    #Database helper functions
    def get_user_by_username(self, username):
        conn = sqlite3.connect(DB_PATH) #Open connection to sqlite db
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,)) #find user by username
        user = cursor.fetchone() #fetch the first row
        conn.close()
        return user #return user data

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

    def get_contacts(self, user_id): #fetches all contacts for a given user from the database
        conn = sqlite3.connect(DB_PATH) #start db connection
        cursor = conn.cursor()

        #get the id, name, and profile picture.. then match user ids
        cursor.execute('''
        SELECT u.id, u.username, u.profile_pic 
        FROM users u JOIN contacts c ON u.id = c.contact_id 
        WHERE c.user_id = ?
        ''', (user_id,))
        contacts = cursor.fetchall() #fetch all the rows
        conn.close()
        return contacts

    def get_messages(self, user1_id, user2_id):
        conn = sqlite3.connect(DB_PATH) #start connection
        cursor = conn.cursor()

        #get all messages from user 1 and 2 or user 2 and 1, and sort by time
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
        username = self.login_username.text() #get username
        password = self.login_password.text() #get password

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter both username and password")
            return

        user = self.get_user_by_username(username) #calls this method
        if not user: #if user not found
            QMessageBox.warning(self, "Error", "User not found")
            return

        #using bcrypt to compare the entered passw (encoded as bytes) and the hash passw stored in user 3
        if bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            self.current_user = {
                'id': user[0], #db id at first column
                'username': user[1], #username at second column
                'phone': user[2], #phone number ...
                'profile_pic': user[4], #profile picture or avatar ...
                'bio': user[5] #biography ...
            }

            #Update UI with user data - calls a method to refresh the main chat interface with the logged in data to ensure that the UI displays current user info immediately after logging
            self.update_main_screen()

            #Connect to socket server - creates a new client socket, passing the user id to establish a real time connection to the server for sending and receiving messages
            self.client_socket = ClientSocket(self.current_user['id'])

            #crreate a background thread to continuously listen for incoming messages
            threading.Thread(
                target=self.client_socket.receive_messages, #specifies the socket receive_message method
                args=(self.handle_received_message,), #passes this method (handle_received_message) to process received messages
                daemon=True #ensures the thread exits when the main app closes
            ).start()

            self.stacked_widget.setCurrentWidget(self.main_screen)
        else:
            QMessageBox.warning(self, "Error", "Incorrect password")

    def handle_signup(self): #this handles the whole signup process
        username = self.signup_username.text() #get username
        phone = self.signup_phone.text() #get phone number
        password = self.signup_password.text() #get password
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

        #Hash password - to store passwords safely. .gensalt() generates a random unique value to prevent hacking of passwords
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        #Save all the information to the database
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
        #Update profile button - updates the profile picture with the user's avatar
        if self.current_user['profile_pic']: #if profile exists in current_user data
            self.user_profile_btn.setIcon(QIcon(self.current_user['profile_pic'])) #set the profile picture
            self.user_profile_btn.setIconSize(QPixmap(self.current_user['profile_pic']).size()) #adjusts the icon size to match the image
        else: #if no profile picture exists
            self.user_profile_btn.setIcon(QIcon(DEFAULT_AVATAR)) #use default pciture instead
            self.user_profile_btn.setIconSize(QPixmap(DEFAULT_AVATAR).size())

        #Update contacts list
        self.contacts_list.clear() #removes all existing items from the contacts list to prepare for fresh data and avoid duplicates
        contacts = self.get_contacts(self.current_user['id']) #get the logged in user's contacts

        #Display each contact in the UI
        for contact in contacts:
            item = QListWidgetItem(contact[1]) #create a list item
            item.setData(Qt.ItemDataRole.UserRole, contact[0])  #Store user_id as hidden data in the item
            self.contacts_list.addItem(item) #adds the item to the list that is now shown

    def open_chat(self, item):
        contact_id = item.data(Qt.ItemDataRole.UserRole) #gets hidden contact id to identify which contact the user clicked to chat with
        contact = self.get_user_by_id(contact_id) #gets the contact's full record from the db

        if not contact: #if contact not found
            QMessageBox.warning(self, "Error", "Contact not found")
            return

        #stores active chat's data in current_chat for later use
        self.current_chat = {
            'id': contact[0], #contact db id
            'name': contact[1] #contact username
        }

        self.chat_contact_name.setText(f"Chat with {contact[1]}") #Updates the chat window's title to show the contact's name
        self.load_chat_messages() #calls the method to fetch and display past messages with a specific contact
        self.stacked_widget.setCurrentWidget(self.chat_screen)

    def load_chat_messages(self):
        self.chat_display.clear() #clears the chat display to prepare for new messages to prevent texts from mixing up when switching chat screens
        messages = self.get_messages(self.current_user['id'], self.current_chat['id']) #get all the messages between the 2 users

        for msg in messages:
            sender_id, content = msg[1], msg[3] #extracts the sender_id and content from each message tuple to determine who sent the message to format it correctly
            if sender_id == self.current_user['id']: #if the sender_id matches the current user id
                #Message from current user (right aligned)
                self.chat_display.append(f"<div style='text-align:right; color:blue;'>You: {content}</div>") #using html/css to style it
            else:
                #Message from contact (left aligned)
                self.chat_display.append(
                    f"<div style='text-align:left; color:green;'>{self.current_chat['name']}: {content}</div>")

    def send_chat_message(self):
        message = self.message_input.text() #gets message from the message input field
        if not message:
            return #exits if the message is empty. It prevents sending blank messages

        #Send via socket - call the send_message method to enable real time communication
        self.client_socket.send_message(self.current_chat['id'], message)

        #Update UI - appends the sent messages to the chat display
        self.chat_display.append(f"<div style='text-align:right; color:blue;'>You: {message}</div>") #align it right for sender
        self.message_input.clear()

    def handle_received_message(self, sender_id, message):
        #if a chat is currently open, and checks if the message sender matches the active chat's contact id
        if hasattr(self, 'current_chat') and str(self.current_chat['id']) == sender_id:
            sender = self.get_user_by_id(int(sender_id)) #gets sender's name/profile from the db
            if sender:
                self.chat_display.append(f"<div style='text-align:left; color:green;'>{sender[1]}: {message}</div>") #align left for receiver

    def change_profile_pic(self): #handles changing profile picture
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Profile Picture", "",
            "Image Files (*.png *.jpg *.jpeg)"
        )

        if file_path:
            try:
                #Create a profile_pictures directory if it doesn't exist
                pics_dir = os.path.join(BASE_DIR, 'profile_pictures') #combines the app's base directory with a profile_pictures subdir
                os.makedirs(pics_dir, exist_ok=True) #creates the dir if it doesn't already exist. exist_ok = True prevents errors if it already exists

                #Save to user-specific file
                dest = os.path.join(pics_dir, f"user_{self.current_user['id']}.jpg")
                shutil.copy(file_path, dest) #copy the original image to the new location

                #Update database - adds the new profile picture to the db
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

        #compare the entered pasword with the stored hash to verify they match
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

        sticker_dialog = QDialog(self) #creates pop up dialog window
        sticker_dialog.setWindowTitle("Select Sticker")
        layout = QGridLayout()

        for i, sticker in enumerate(stickers): #loop through stickers
            btn = QPushButton(sticker) #creates button for each sticker
            btn.setFont(QFont("Segoe UI Emoji", 24))
            btn.clicked.connect(lambda _, s=sticker: self.send_sticker(s, sticker_dialog)) #when clicked, send sticker
            layout.addWidget(btn, i // 4, i % 4) #adds the button to the grid

        sticker_dialog.setLayout(layout)
        sticker_dialog.exec()

    def send_sticker(self, sticker, dialog):
        try:
            self.client_socket.send_message(self.current_chat['id'], sticker) #sends sticker through the socket to the current chat
            self.chat_display.append(
                f"<div style='text-align:right; color:blue;'>You: {sticker}</div>"
            ) #appends the sticker right aligned to the chat display
        except Exception as e:
            print(f"Error sending sticker: {e}")
        finally:
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