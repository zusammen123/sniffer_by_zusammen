# -*- coding: utf-8 -*-


from SnifferGui import *
from SnifferController import *
from Sniffer import *
import sys
import os


if __name__ == "__main__":
    try:
    
        os.chdir(sys.path[0])
        app = QtWidgets.QApplication(sys.argv)
        ui = SnifferGui() #v
        MainWindow = QtWidgets.QMainWindow()
        ui.setupUi(MainWindow)
        MainWindow.show()
        sc = SnifferController(ui)#C
        sc.loadAdapterIfaces()
        sc.setConnection()
        sys.exit(app.exec_())
    except ImportError as  e:
            QtWidgets.QMessageBox.critical(None,"错误",str(e))
    except Exception as e2:
            QtWidgets.QMessageBox.critical(None,"错误",str(e2))
    
    
