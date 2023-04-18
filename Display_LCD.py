from RPLCD import *
import time
from RPLCD.i2c import CharLCD


class Display(object):
    def __init__(self):
        self.lcd = CharLCD('PCF8574', 0x27)
        self.lcd.cursor_pos = (0, 0)

        self.buffer = ['', '', '', '']

    def write_line(self, line=''):
        self.buffer[0] = self.buffer[1]
        self.buffer[1] = self.buffer[2]
        self.buffer[2] = self.buffer[3]
        self.buffer[3] = line
        self.write_lcd(20)

    def write_lcd(self, num_cols):
        self.lcd.home()
        for row in self.buffer:
            self.lcd.write_string(row.ljust(num_cols)[:num_cols])
            self.lcd.write_string('\r\n')

    def write_scroll(self, text):
        if len(text) < 20:
            self.lcd.write_string(text)
        for i in range(len(text) - 20 + 1):
            self.buffer[0] = text[i:i + 20]
            self.buffer[1] = text[i:i + 20]
            self.buffer[2] = text[i:i + 20]
            self.buffer[3] = text[i:i + 20]
            self.write_lcd(20)
            time.sleep(0.3)


disp = Display()
disp.lcd.home()
disp.write_line('Server is running!')

