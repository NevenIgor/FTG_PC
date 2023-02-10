import os
import re
import json
import zlib
from PyQt5 import QtCore, QtGui, QtWidgets
from settings import *



class SettingPanel(QtWidgets.QWidget):
    def __init__(self, parent=None, signal=None):
        super().__init__(parent, QtCore.Qt.Window)
        self.parent = parent
        self.setting = Ui_Form()
        self.setting.setupUi(self)
        self.setWindowModality(2)

        # Сигнал для возврата в интерфейс
        self.signal = signal

        # Отключаем стандартные границы окна программы
        self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.center()

        self.setting.pushButton_4.clicked.connect(self.load_img)
        self.setting.pushButton_7.clicked.connect(lambda: self.close())
        self.setting.pushButton_6.clicked.connect(self.save_config)
        self.setting.pushButton_8.clicked.connect(self.connect)

        self.upload_img()

        if os.path.exists(os.path.join("Data", "config.json")):
            with open(os.path.join("Data", "config.json")) as file:
                data = json.load(file)
                self.setting.lineEdit_4.setText(data['username'])
                self.setting.lineEdit_2.setText(data['server_ip'])
                self.setting.lineEdit_3.setText(str(data['server_port']))

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

    def connect(self):
        check = self.save_config()
        if check:
            self.signal.emit({'type': 'CONNECT'})

    def load_img(self):
        f_name = QtWidgets.QFileDialog.getOpenFileName(self, 'Open file', '')[0]
        if f_name:
            pixmap = QtGui.QPixmap()
            pixmap.convertFromImage(QtGui.QImage(f_name))
            if pixmap.size() != QtCore.QSize(64, 64):
                pixmap.scaled(QtCore.QSize(64, 64))
            pixmap.save(f'Data/profileImages/{self.parent.id}.png')
            crc = zlib.crc32(open(f'Data/profileImages/{self.parent.id}.png', 'rb').read())
            print(crc)
            self.parent.img = crc
        self.upload_img()

    def upload_img(self):
        self.setting.label.setText('')
        pixmap = QtGui.QPixmap()
        if self.parent.img:
            pixmap.convertFromImage(QtGui.QImage(f'Data/profileImages/{self.parent.id}.png'))
        else:
            pixmap.convertFromImage(QtGui.QImage('Data/profileImages/DefaultImages/user.png'))
        self.setting.label.setPixmap(pixmap)
        self.setting.label.update()

    def save_config(self):
        username = self.setting.lineEdit_4.text()
        server_ip = self.setting.lineEdit_2.text()
        server_port = self.setting.lineEdit_3.text()
        regular_ip = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

        # Обновляем датчики, для того чтобы пользователь видел какие поля правильные
        self.setting.lineEdit_2.setStyleSheet("border-radius: 7px;")
        self.setting.lineEdit_3.setStyleSheet("border-radius: 7px;")
        self.setting.lineEdit_4.setStyleSheet("border-radius: 7px;")

        # Проверяем корректность ввода пользователя
        if 3 <= len(username) <= 16:
            if not re.match(regular_ip, self.setting.lineEdit_2.text()) is None:
                if server_port.isdecimal() and int(server_port) <= 65535:
                    with open(os.path.join("Data", "config.json")) as file:
                        data = json.load(file)
                        passwd = data['pass']
                        priv_ds = data['priv_key']
                        img = self.parent.img
                        print(img)
                    with open(os.path.join("Data", "config.json"), 'w') as file:
                        payload = {
                            'userid': self.parent.id,
                            'username': username,
                            'pass': passwd,
                            'img': img,
                            'priv_key': priv_ds,
                            'server_ip': server_ip,
                            'server_port': int(server_port)
                        }
                        data = json.dumps(payload)
                        file.write(data)

                    # Закрываем окно с настройками
                    self.close()
                    self.signal.emit({'type': 'UPDATE_CONFIG'})
                    return True

                else:
                    self.setting.lineEdit_3.setStyleSheet("border: 2px solid red; border-radius: 7px;")
                    self.setting.lineEdit_3.setText("Проверьте правильность ввода SERVER_PORT")
                    return False
            else:
                self.setting.lineEdit_2.setStyleSheet("border: 2px solid red; border-radius: 7px;")
                self.setting.lineEdit_2.setText("Проверьте правильность ввода SERVER_IP")
                return False
        else:
            self.setting.lineEdit_4.setStyleSheet("border: 2px solid red; border-radius: 7px;")
            self.setting.lineEdit_4.setText("Слишком длинный либо слишком короткий ник")
            return False
