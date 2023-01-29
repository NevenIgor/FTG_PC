import socket
import json
import time
import os

from PyQt5 import QtCore, QtGui, QtWidgets
from GUI import *

from ThreadMonitor import MessageMonitor
from SettingsPanel import SettingPanel

from CryptoCore.DH import DHEndpoint
from CryptoCore.EC import ECPoint


class Client(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ip = '127.0.0.1'
        self.port = 1337
        self.id = None
        self.name = None
        self.connected = False
        self.DEFAULT_SIZE = 4096

        self.update_config()

        self.master_key = None
        self.srv_pub_ds = None

        self.users_id = {}
        self.users_id_off = {}

        self.inv_users_id = {}
        self.inv_users_id_off = {}

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.center()

        self.ui.pushButton.clicked.connect(self.send)
        self.ui.pushButton_2.clicked.connect(self.setting_panel)
        self.ui.pushButton_3.clicked.connect(lambda: self.close())
        self.ui.pushButton_5.clicked.connect(lambda: self.showMinimized())
        self.ui.listWidget_2.clicked.connect(self.renew)
        self.ui.listWidget_3.clicked.connect(self.renew_off)
        self.items = list()

        self.btn_locker(self.ui.pushButton, True)

        self.connect_monitor = MessageMonitor(master_key=self.master_key, pub_ds=self.srv_pub_ds)
        self.connect_monitor.mysignal.connect(self.signal_handler)
        self.connect_monitor.server_socket = self.client

        self.connect()

    def send_data(self, payload):
        data = json.dumps(payload)
        self.client.send(data.encode())

    def recv_data(self):
        recv = self.client.recv(self.DEFAULT_SIZE).decode()
        print(recv)
        return json.loads(recv)

    def connect(self):
        if not self.connected:
            try:
                self.client.connect((self.ip, self.port))
                self.connected = True
                self.btn_locker(self.ui.pushButton, False)
            except Exception as e:
                print(e)
            if self.connected:
                if not self.id:
                    payload = {
                        'type': 'SET_NEW_USER'
                    }
                else:
                    payload = {
                        'type': 'CONNECT',
                        'id': self.id
                    }
                self.send_data(payload)
                recv = self.recv_data()
                if recv['status'] == 'OK':
                    if recv['type'] == 'CHANGE_CIPHER_SPEC':
                        if recv.get('id', None):
                            self.id = recv['id']
                        data = recv['data']
                        pub_ds_spec = data['pub_ds']
                        self.srv_pub_ds = ECPoint(pub_ds_spec[0],
                                                  pub_ds_spec[1],
                                                  pub_ds_spec[2],
                                                  pub_ds_spec[3],
                                                  pub_ds_spec[4])
                        dh = DHEndpoint(data['p'], data['g'])
                        pub = data['pub']
                        payload = {
                            'type': 'SPEC_RESPONSE',
                            'data': {
                                'pub': dh.pub_key,
                                'name': self.name,
                            },
                            'status': 'OK'
                        }
                        self.set_config()
                        self.send_data(payload)
                        self.master_key = dh.generate_full_key(pub).to_bytes(256, 'big')

                        self.connect_monitor.pub_ds = self.srv_pub_ds
                        self.connect_monitor.symmetric_key = self.master_key
                        self.connect_monitor.start()
                        self.update_config()

    def update_config(self):
        if os.path.exists(os.path.join("Data", "config.json")):
            with open(os.path.join("Data", "config.json")) as file:
                data = json.load(file)
                self.id = data['userid']
                self.ip = data['server_ip']
                self.port = data['server_port']
                self.name = data['username']
                if self.connected:
                    payload = {
                        'type': 'UPDATE_USERNAME',
                        'userid': self.id,
                        'username': self.name,
                        'status': 'OK'
                    }
                    self.connect_monitor.send_encrypt(payload)

    def set_config(self):
        with open(os.path.join("Data", "config.json"), 'w') as file:
            payload = {
                'userid': self.id,
                'username': self.name,
                'server_ip': self.ip,
                'server_port': self.port
            }
            data = json.dumps(payload)
            file.write(data)

    def setting_panel(self):
        setting_win = SettingPanel(self, self.connect_monitor.mysignal)
        setting_win.show()

    def keyPressEvent(self, event):
        val = event.key()
        if val == 16777220:
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

    def renew_off(self):
        self.ui.listWidget_3.currentItem().setBackground(QtGui.QColor('#2C313C'))
        userid = self.ui.listWidget_3.currentItem().userid
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
            self.connect()

        elif value['type'] == 'SET_MASTER_KEY':
            self.master_key = value['master_key']

        elif value['type'] == 'MESSAGE_UPDATE_RESPONSE':
            messages = value['messages']
            if messages:
                for message in messages:
                    if message[2] == self.id:
                        item = QtWidgets.QListWidgetItem()
                        item.setTextAlignment(QtCore.Qt.AlignLeft)
                        item.setText(f"(ВЫ):\n{message[3]}")
                        self.ui.listWidget.addItem(item)
                    else:
                        item = QtWidgets.QListWidgetItem()
                        item.setTextAlignment(QtCore.Qt.AlignRight)
                        item.setText(f"{self.users_id.get(message[2], self.users_id_off.get(message[2], 'UNKNOWN'))}"
                                     f":\n{message[3]}")
                        self.ui.listWidget.addItem(item)
            self.ui.listWidget.scrollToBottom()

        elif value['type'] == 'MESSAGE':
            text = value['data']['text']
            uid = value['userid']
            img = value['data']['img']
            members = value['members']
            if self.ui.listWidget_2.currentItem():
                if members == -1 and self.ui.listWidget_2.currentItem().userid != uid:
                    item = QtWidgets.QListWidgetItem()
                    item.setTextAlignment(QtCore.Qt.AlignRight)
                    item.setText(f"{self.users_id.get(uid, self.users_id_off.get(uid, 'UNKNOWN'))}:\n{text}")
                    self.ui.listWidget.addItem(item)
                    self.ui.listWidget.scrollToBottom()
                else:
                    if self.ui.listWidget_2.currentItem().userid == uid and members != -1:
                        item = QtWidgets.QListWidgetItem()
                        item.setTextAlignment(QtCore.Qt.AlignRight)
                        item.setText(f"{self.users_id.get(uid, self.users_id_off.get(uid, 'UNKNOWN'))}:\n{text}")
                        self.ui.listWidget.addItem(item)
                        self.ui.listWidget.scrollToBottom()
                    else:
                        if members != -1:
                            for item in self.items:
                                if item.userid == uid:
                                    item.setBackground(QtGui.QColor('green'))
            else:
                if members != -1:
                    for item in self.items:
                        if item.userid == uid:
                            item.setBackground(QtGui.QColor('green'))

        elif value['type'] == 'UPDATE_MEMBERS':
            self.items.clear()
            self.ui.listWidget_2.blockSignals(True)
            self.ui.listWidget_3.blockSignals(True)
            self.ui.listWidget_2.clear()
            self.ui.listWidget_3.clear()
            self.ui.listWidget_3.blockSignals(False)
            self.ui.listWidget_2.blockSignals(False)
            self.users_id = value['online']
            self.users_id = {int(k): v for k, v in self.users_id.items()}
            self.users_id_off = value['offline']
            self.users_id_off = {int(k): v for k, v in self.users_id_off.items()}
            self.inv_users_id = {val: key for key, val in self.users_id.items()}
            self.inv_users_id_off = {val: key for key, val in self.users_id_off.items()}
            del self.users_id[self.id]
            item = UserItem(-1)
            item.setTextAlignment(QtCore.Qt.AlignHCenter)
            item.setText(f"Общий чат\n")
            self.ui.listWidget_2.addItem(item)
            for user in self.users_id:
                item = UserItem(user)
                item.setTextAlignment(QtCore.Qt.AlignHCenter)
                item.setText(self.users_id[user])
                self.ui.listWidget_2.addItem(item)
                self.items.append(item)
            for user in self.users_id_off:
                item = UserItem(user)
                item.setTextAlignment(QtCore.Qt.AlignHCenter)
                item.setText(self.users_id_off[user])
                self.ui.listWidget_3.addItem(item)
                self.items.append(item)

    def send(self):
        if self.ui.listWidget_2.currentItem():
            userid = self.inv_users_id.get(self.ui.listWidget_2.currentItem().text())
        elif self.ui.listWidget_3.currentItem():
            userid = self.inv_users_id_off.get(self.ui.listWidget_3.currentItem().text())
        else:
            userid = -1
        if not userid:
            userid = -1
        members = userid
        img = None
        text = self.ui.lineEdit.text()
        self.ui.lineEdit.clear()
        item = QtWidgets.QListWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeft)
        item.setText(f"(ВЫ):\n{text}")
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
            'status': 'OK'
        }
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


class UserItem(QtWidgets.QListWidgetItem):
    def __init__(self, userid, parent=None):
        super().__init__(parent=parent)
        self.userid = userid


if __name__ == '__main__':
    import sys

    app = QtWidgets.QApplication(sys.argv)
    myapp = Client()
    myapp.show()
    sys.exit(app.exec_())


