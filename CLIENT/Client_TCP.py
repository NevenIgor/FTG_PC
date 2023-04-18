import socket
import json
import time
import os
import zlib
import getpass

from PyQt5 import QtCore, QtGui, QtWidgets
from GUI import *

from ThreadMonitor import MessageMonitor
from SettingsPanel import SettingPanel

from CryptoCore.DH import DHEndpoint
from CryptoCore.DS import DSGOST
from CryptoCore.EC import ECPoint
from CryptoCore.BC import BlockCipher
from CryptoCore.HASH import HGOST


class Client(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.setWindowTitle('FTG')
        self.setWindowIcon(QtGui.QIcon('Data/Sources/icon.png'))

        self.ip = '127.0.0.1'
        self.port = 1337
        self.id = None
        self.img = None
        self.name = None
        self.passwd = None
        self.connected = False
        self.authorised = False

        self.DEFAULT_SIZE = 4096

        self.master_key = None
        self.priv_ds = None
        self.srv_pub = None

        self.h = HGOST()

        self.users_id = {}
        self.users_id_off = {}

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.center()

        self.ui.listWidget_2.setIconSize(QtCore.QSize(48, 48))
        self.ui.listWidget.setIconSize(QtCore.QSize(32, 32))
        self.ui.pushButton.clicked.connect(self.send)
        self.ui.pushButton_2.clicked.connect(self.setting_panel)
        self.ui.pushButton_3.clicked.connect(lambda: self.close())
        self.ui.pushButton_5.clicked.connect(lambda: self.showMinimized())
        self.ui.listWidget_2.clicked.connect(self.renew)
        self.items = list()

        self.btn_locker(self.ui.pushButton, True)

        self.update_config()

        self.connect_monitor = MessageMonitor(parent=self)
        self.connect_monitor.mysignal.connect(self.signal_handler)

        self.connect()

    def send_data(self, payload):
        data = json.dumps(payload)
        self.client.send(data.encode())

    def recv_data(self):
        recv = self.client.recv(self.DEFAULT_SIZE).decode()
        return json.loads(recv)

    def connect(self):
        if not self.connected:
            try:
                self.client.connect((self.ip, self.port))
                self.connected = True
            except Exception as e:
                print(e)
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    self.client.connect((self.ip, self.port))
                    self.connected = True
                except Exception as e:
                    print(e)
            if self.connected:
                if not self.id:
                    new = True
                    payload = {
                        'type': 'SET_NEW_USER'
                    }
                    self.send_data(payload)
                else:
                    new = False
                    payload = {
                        'type': 'CONNECT',
                        'id': self.id
                    }
                    self.send_data(payload)
                    recv = self.recv_data()
                    if recv['status'] == 'OK':
                        if recv['type'] == 'AUTH_CHALLENGE':
                            data = recv['data']
                            challenge = data['challenge']
                            h = HGOST()
                            response = h.hash(self.passwd + challenge)
                            ds = DSGOST(p=57896044618658097711785492504343953926634992332820282019728792003956564821041,
                                        a=7,
                                        b=43308876546767276905765904595650931995942111794451039583252968842033849580414,
                                        q=57896044618658097711785492504343953927082934583725450622380973592137631069619,
                                        p_x=2,
                                        p_y=4018974056539037503335449422937059775635739389905545080690979365213431566280)
                            sign = ds.sign(response, self.priv_ds)
                            payload = {
                                'type': 'AUTH_RESPONSE',
                                'data': {
                                    'response': response,
                                    'sign': sign
                                },
                                'status': 'OK'
                            }
                            self.send_data(payload)
                    elif recv['status'] == 'ERROR':
                        print(f'Ошибка: {recv["err"]}')
                        self.client.close()
                        self.connected = False
                        return
                recv = self.recv_data()
                if recv['status'] == 'OK':
                    self.authorised = True
                    if recv['type'] == 'CHANGE_CIPHER_SPEC':
                        if recv.get('id', None):
                            self.id = recv['id']
                        data = recv['data']
                        dh = DHEndpoint(data['p'], data['g'])
                        pub = data['pub_dh']
                        pub_spec = data['pub_ds']
                        self.srv_pub = ECPoint(pub_spec[0],
                                               pub_spec[1],
                                               self.connect_monitor.ds.a,
                                               self.connect_monitor.ds.b,
                                               self.connect_monitor.ds.p,)
                        payload = {
                            'type': 'SPEC_RESPONSE',
                            'data': {
                                'pub': dh.pub_key,
                                'name': self.name,
                                'img': self.img
                            },
                            'status': 'OK'
                        }
                        self.send_data(payload)
                        self.master_key = dh.generate_full_key(pub).to_bytes(32, 'big')
                        bc = BlockCipher()
                        if new:
                            recv = bc.decrypt(self.client.recv(self.DEFAULT_SIZE), self.master_key, 'CBC')
                            recv = json.loads(recv.decode())
                            if recv['status'] == 'OK':
                                if recv['type'] == 'DS_PRIVATE_KEY':
                                    data = recv['data']
                                    self.passwd = data['pass']
                                    self.priv_ds = data['priv_ds']
                                    self.set_config()
                        recv = bc.decrypt(self.client.recv(self.DEFAULT_SIZE), self.master_key, 'CBC')
                        recv = json.loads(recv.decode())
                        if recv['status'] == 'OK':
                            if recv['type'] == 'IMG_ASK':
                                if os.path.exists(os.path.join("Data", "profileImages", f'{self.id}.png')):
                                    with open(os.path.join("Data", "profileImages", f'{self.id}.png'), 'rb') as f:
                                        data = f.read()
                                    enc_data = bc.encrypt(data, self.master_key, 'CBC')
                                    with open(os.path.join("Data", "profileImages", f'{self.id}.enc'), 'wb') as f:
                                        f.write(enc_data)
                                    with open(os.path.join("Data", "profileImages", f'{self.id}.enc'), 'rb') as f:
                                        while True:
                                            data = f.read(self.DEFAULT_SIZE)
                                            if not data:
                                                break
                                            sent = self.client.send(data)
                                            assert sent == len(data)
                                    time.sleep(0.5)
                                    self.client.send(b'EOF')
                                    recv = bc.decrypt(self.client.recv(self.DEFAULT_SIZE), self.master_key, 'CBC')
                                    recv = json.loads(recv.decode())
                                    if recv['status'] == 'OK':
                                        if recv['type'] == 'CONNECT_CONFIRM':
                                            self.connect_monitor.priv_ds = self.priv_ds
                                            self.connect_monitor.srv_pub = self.srv_pub
                                            self.connect_monitor.symmetric_key = self.master_key
                                            self.connect_monitor.server_socket = self.client
                                            self.connect_monitor.start()
                                            self.update_config()
                                            self.btn_locker(self.ui.pushButton, False)
                                else:
                                    self.client.send(b'EOF')
                                    recv = bc.decrypt(self.client.recv(self.DEFAULT_SIZE), self.master_key, 'CBC')
                                    recv = json.loads(recv.decode())
                                    if recv['status'] == 'OK':
                                        if recv['type'] == 'CONNECT_CONFIRM':
                                            self.connect_monitor.priv_ds = self.priv_ds
                                            self.connect_monitor.srv_pub = self.srv_pub
                                            self.connect_monitor.symmetric_key = self.master_key
                                            self.connect_monitor.server_socket = self.client
                                            self.connect_monitor.start()
                                            self.update_config()
                                            self.btn_locker(self.ui.pushButton, False)
                            elif recv['type'] == 'CONNECT_CONFIRM':
                                self.connect_monitor.priv_ds = self.priv_ds
                                self.connect_monitor.srv_pub = self.srv_pub
                                self.connect_monitor.symmetric_key = self.master_key
                                self.connect_monitor.server_socket = self.client
                                self.connect_monitor.start()
                                self.update_config()
                                self.btn_locker(self.ui.pushButton, False)
                else:
                    app.exit()

    def update_config(self):
        if os.path.exists(os.path.join("Data", "config.json")):
            with open(os.path.join("Data", "config.json")) as file:
                data = json.load(file)
                self.id = data['userid']
                self.ip = data['server_ip']
                self.port = data['server_port']
                self.name = data['username']
                self.img = data['img']
                self.passwd = data['pass']
                self.priv_ds = data['priv_key']

                if self.connected:
                    if self.authorised:
                        payload = {
                            'type': 'UPDATE_USERNAME',
                            'userid': self.id,
                            'username': self.name,
                            'img': self.img,
                            'status': 'OK'
                        }
                        self.connect_monitor.send_encrypt(payload)
        else:
            self.name = getpass.getuser()
            self.set_config()

    def set_config(self):
        if not os.path.exists('Data'):
            os.mkdir('Data')
            os.mkdir('Data\\profileImages')
        if not os.path.exists(os.path.join("Data", "profileImages")):
            os.mkdir('Data\\profileImages')
        with open(os.path.join("Data", "config.json"), 'w') as file:
            payload = {
                'userid': self.id,
                'username': self.name,
                'img': self.img,
                'pass': self.passwd,
                'priv_key': self.priv_ds,
                'server_ip': self.ip,
                'server_port': self.port
            }
            data = json.dumps(payload)
            file.write(data)

    def find_img(self, id):
        if id != 1:
            if os.path.exists(os.path.join("Data", "profileImages", f'{id}.png')):
                icon = QtGui.QPixmap(os.path.join("Data", "profileImages", f'{id}.png'))
            else:
                icon = QtGui.QPixmap(os.path.join("Data", "profileImages", 'DefaultImages', 'user.png'))
            if id in self.users_id:
                painter = QtGui.QPainter()
                painter.begin(icon)
                painter.setPen(QtGui.QColor('green'))
                painter.setBrush(QtGui.QBrush(QtGui.QColor('green')))
                painter.drawEllipse(47, 47, 15, 15)
                painter.end()
            return QtGui.QIcon(icon)

    def setting_panel(self):
        setting_win = SettingPanel(self, self.connect_monitor.mysignal)
        setting_win.show()

    def keyPressEvent(self, event):
        val = event.key()
        if val == 16777220:
            if self.ui.pushButton.isEnabled():
                self.send()

    def center(self):
        qr = self.frameGeometry()
        cp = QtWidgets.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def mousePressEvent(self, event):
        self.oldPos = event.globalPos()

    def mouseMoveEvent(self, event):
        try:
            delta = QtCore.QPoint(event.globalPos() - self.oldPos)
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.oldPos = event.globalPos()
        except AttributeError:
            pass

    def btn_locker(self, btn, lock_status):
        default_style = """
        QPushButton{
            color: white;
            border-radius: 7px;
            background-color: #595F76;
        }
        QPushButton:hover{
            background-color: #50566E;
        }      
        QPushButton:pressed{
            background-color: #434965;
        }
        """

        lock_style = """
        color: #9EA2AB;
        border-radius: 7px;
        background-color: #2C313C;
        """

        if lock_status:
            btn.setDisabled(True)
            btn.setStyleSheet(lock_style)
        else:
            btn.setDisabled(False)
            btn.setStyleSheet(default_style)

    def renew(self):
        self.ui.listWidget_2.currentItem().setBackground(QtGui.QColor('#2C313C'))
        userid = self.ui.listWidget_2.currentItem().userid
        self.ui.listWidget.clear()
        payload = {
            'type': 'UPDATE_MESSAGES',
            'userid': self.id,
            'chatid': userid,
            'status': 'OK'
        }
        self.connect_monitor.send_encrypt(payload)

    def signal_handler(self, value):
        if value['type'] == 'UPDATE_CONFIG':
            self.update_config()

        elif value['type'] == 'CONNECT':
            if self.authorised:
                self.connect()
            else:
                self.connected = False
                self.connect()

        elif value['type'] == 'SET_MASTER_KEY':
            self.master_key = value['master_key']

        elif value['type'] == 'MESSAGE_UPDATE_RESPONSE':
            messages = value['messages']
            if messages:
                for message in messages:
                    if message[2] == self.id:
                        item = MessageItem(0, message[3], self)
                        self.ui.listWidget.addItem(item)
                    else:
                        item = MessageItem(message[2], f"{self.users_id.get(message[2], self.users_id_off.get(message[2], ('UNKNOWN', )))[0]} :\n{message[3]}", self)
                        self.ui.listWidget.addItem(item)
            self.ui.listWidget.scrollToBottom()

        elif value['type'] == 'MESSAGE':
            text = value['data']['text']
            uid = value['userid']
            img = value['data']['img']
            members = value['members']
            if self.ui.listWidget_2.currentItem():
                if members != -1:
                    if self.ui.listWidget_2.currentItem().userid == uid:
                        item = MessageItem(uid, f"{self.users_id.get(uid, self.users_id_off.get(uid, ('UNKNOWN', )))[0]}:\n{text}", self)
                        self.ui.listWidget.addItem(item)
                        self.ui.listWidget.scrollToBottom()
                    else:
                        for item in self.items:
                            if item.userid == uid:
                                item.setBackground(QtGui.QColor('green'))
                else:
                    if self.ui.listWidget_2.currentItem().userid == -1:
                        item = MessageItem(uid, f"{self.users_id.get(uid, self.users_id_off.get(uid, ('UNKNOWN', )))[0]}:\n{text}", self)
                        self.ui.listWidget.addItem(item)
                        self.ui.listWidget.scrollToBottom()
            else:
                if members != -1:
                    for item in self.items:
                        if item.userid == uid:
                            item.setBackground(QtGui.QColor('green'))

        elif value['type'] == 'UPDATE_MEMBERS':
            self.users_id = value['online']
            self.users_id = {int(k): v for k, v in self.users_id.items()}
            self.users_id_off = value['offline']
            self.users_id_off = {int(k): v for k, v in self.users_id_off.items()}
            del self.users_id[self.id]
            no_img = []
            for user in self.users_id:
                crc_orig = self.users_id[user][1]
                if not crc_orig:
                    if os.path.exists(os.path.join("Data", "profileImages", f'{user}.png')):
                        os.remove(os.path.join("Data", "profileImages", f'{user}.png'))
                else:
                    if os.path.exists(os.path.join("Data", "profileImages", f'{user}.png')):
                        crc_local = zlib.crc32(open(os.path.join("Data", "profileImages", f'{user}.png'), 'rb').read())
                        if crc_local != crc_orig:
                            no_img.append(user)
                    else:
                        no_img.append(user)
            for user in self.users_id_off:
                crc_orig = self.users_id_off[user][1]
                if not crc_orig:
                    if os.path.exists(os.path.join("Data", "profileImages", f'{user}.png')):
                        os.remove(os.path.join("Data", "profileImages", f'{user}.png'))
                else:
                    if os.path.exists(os.path.join("Data", "profileImages", f'{user}.png')):
                        crc_local = zlib.crc32(open(os.path.join("Data", "profileImages", f'{user}.png'), 'rb').read())
                        if crc_local != crc_orig:
                            no_img.append(user)
                    else:
                        no_img.append(user)
            if no_img:
                payload = {
                    'type': 'IMG_UPDATE_REQUEST',
                    'data': {
                        'users_img': no_img,
                    },
                    'status': 'OK'
                }
                self.connect_monitor.queue = payload
            self.update_user_list()
            self.update_messages()

        elif value['type'] == 'UPDATE_USERLIST':
            self.update_user_list()
            self.update_messages()

    def update_user_list(self):
        self.items.clear()
        self.ui.listWidget_2.blockSignals(True)
        self.ui.listWidget_2.clear()
        self.ui.listWidget_2.blockSignals(False)
        item = UserItem(-1)
        item.setTextAlignment(QtCore.Qt.AlignHCenter)
        item.setText(f"Общий чат\n")
        self.ui.listWidget_2.addItem(item)
        for user in self.users_id:
            item = UserItem(user)
            item.setText(self.users_id[user][0])
            self.ui.listWidget_2.addItem(item)
            self.items.append(item)
        for user in self.users_id_off:
            item = UserItem(user, online=False)
            item.setText(self.users_id_off[user][0])
            self.ui.listWidget_2.addItem(item)
            self.items.append(item)

    def update_messages(self):
        items = list(self.ui.listWidget.item(i) for i in range(self.ui.listWidget.count()))
        self.ui.listWidget.clear()
        for item in items:
            self.ui.listWidget.addItem(MessageItem(item.user_id, item.text, self))

    def send(self):
        if self.ui.listWidget_2.currentItem():
            userid = self.ui.listWidget_2.currentItem().userid
        else:
            userid = -1
        if not userid:
            userid = -1
        members = userid
        img = None
        text = self.ui.lineEdit.toPlainText()
        self.ui.lineEdit.clear()
        item = MessageItem(0, text, self)
        self.ui.listWidget.addItem(item)
        self.ui.listWidget.scrollToBottom()
        payload = {
            'type': 'MESSAGE',
            'userid': self.id,
            'members': members,
            'data': {
                'text': text,
                'img': img,
            },
            'sign': None,
            'status': 'OK'
        }
        h = int.from_bytes(self.h.hash(json.dumps(payload['data']).encode()), 'big')
        r, s = self.connect_monitor.ds.sign(h, self.priv_ds)
        payload['sign'] = (r, s)
        self.connect_monitor.send_encrypt(payload)

    def closeEvent(self, value: QtGui.QCloseEvent):
        try:
            payload = {'type': 'EXIT', 'status': 'OK'}
            self.connect_monitor.send_encrypt(payload)
            self.hide()
            time.sleep(3)
            self.client.close()
            self.close()
        except Exception as err:
            print('Error:', err)


class MessageItem(QtWidgets.QListWidgetItem):
    def __init__(self, user_id, text, parent=None):
        super().__init__()

        self.parent = parent
        self.user_id = user_id
        self.text = text

        if user_id == 0:
            self.my_message = True
        else:
            self.my_message = False
            self.user_id = user_id

        if not self.my_message:
            self.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
            self.setIcon(self.parent.find_img(self.user_id))
        else:
            self.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        self.setText(text)

    def repaint(self):
        if not self.my_message:
            self.setIcon(self.parent.find_img(self.user_id))


class UserItem(QtWidgets.QListWidgetItem):
    def __init__(self, userid, online=True, parent=None):
        super().__init__(parent=parent)
        self.userid = userid

        self.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignVCenter)

        if self.userid != -1:
            if os.path.exists(os.path.join("Data", "profileImages", f'{self.userid}.png')):
                icon = QtGui.QPixmap(os.path.join("Data", "profileImages", f'{self.userid}.png'))
            else:
                icon = QtGui.QPixmap(os.path.join("Data", "profileImages", 'DefaultImages', 'user.png'))
            if online:
                painter = QtGui.QPainter()
                painter.begin(icon)
                painter.setPen(QtGui.QColor('green'))
                painter.setBrush(QtGui.QBrush(QtGui.QColor('green')))
                painter.drawEllipse(47, 47, 15, 15)
                painter.end()
            ico = QtGui.QIcon(icon)
            self.setIcon(ico)


if __name__ == '__main__':
    import sys

    app = QtWidgets.QApplication(sys.argv)
    myapp = Client()
    myapp.show()
    sys.exit(app.exec_())
