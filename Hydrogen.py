import base64
from os import urandom, getenv, chdir, getcwd, remove, path
import threading

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from SqlCmd import DatabaseManagement
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtWidgets import QMessageBox
    from Ersr import Eraser
except ImportError:
    print("Please Install Required Modules Below To Run This Program : ")
    print("1. Cryptography For Encryption Support.")
    print("2. PyQt5 For GUI Support")
    print("3. SqlCmd (ensure it exists in hydrogen directory )")
    print("4. Sqlite3 For Database Support.")
    print("\n To Install Use : (pip install modulename)")
    input()
    pass

program_config = 'Hydrogen.conf'
database_name = 'secured.db'
database_status = True
DBEraser = Eraser(database_name)
mkey = b""  # !responsible for storing key for encryption mechanism. ( don't touch it unless you know what you are doing.)

try:
    key_location = getenv('userprofile')
    chdir(key_location)
except:
    # !maintain current directory.
    pass
SqlMgmt = DatabaseManagement(database_name)


class DatabaseAccess(object):
    """
     This method is causing errors in functioning hence delayed this till i solve the matter.

     This method is responsible for encryption of database, after use of sqlite and decryption of database before the use of sqlite
     it will ensure that your data will not be stored in plaintext, cuz login mechanism is safe .
    """
    orginal_db_name = database_name
    newdatabase_name = orginal_db_name + ".enc"

    def __init__(self, mkey):
        self.mkey = mkey
        pass
"""
    def LockDatabase(self):
        # print("locking")
        with open(DatabaseAccess.orginal_db_name, "rb") as a:
            plaintextdata = a.read()
        # database removal code call here.
        f = Fernet(self.mkey)
        enc_db = f.encrypt(plaintextdata)
        self.newdatabase_name = DatabaseAccess.orginal_db_name
        with open(DatabaseAccess.newdatabase_name, "wb") as b:
            b.write(enc_db)
        if path.isfile(DatabaseAccess.orginal_db_name):
            SqlMgmt.DeleteDatabase()

        pass
"""
"""
    def UnlockDatabase(self):
        with open(DatabaseAccess.newdatabase_name, "rb") as c:
            self.enctext = c.read()
        # encrypted database removal here.
        remove(DatabaseAccess.newdatabase_name)
        f = Fernet(self.mkey)
        try:
            dec_db = f.decrypt(self.enctext)
        except InvalidToken:
            # !wrong key provided to unlock database.
            database_status = False  # !it will not let program to open due to locked database.
            self.error_msgBox = QMessageBox()
            self.error_msgBox.setIcon(QMessageBox.Critical)
            self.error_msgBox.setText("wrong Key Provided, Database Is Encrypted Till Valid Key Provided")
            self.error_msgBox.setWindowTitle("Possible Security Breach")
            self.error_msgBox.setStandardButtons(QMessageBox.Ok)
            self.error_msgBox.show()

        with open(DatabaseAccess.orginal_db_name, "wb") as d:
            d.write(dec_db)
        pass
"""

class SB_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        Dialog.resize(638, 480)
        self.formGroupBox = QtWidgets.QGroupBox(Dialog)
        self.formGroupBox.setGeometry(QtCore.QRect(60, 170, 511, 221))
        self.formGroupBox.setObjectName("formGroupBox")
        self.formLayout = QtWidgets.QFormLayout(self.formGroupBox)
        self.formLayout.setObjectName("formLayout")
        self.label = QtWidgets.QLabel(self.formGroupBox)
        font = QtGui.QFont()
        font.setFamily("Verdana")
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.label)
        self.comboBox_accountype = QtWidgets.QComboBox(self.formGroupBox)
        font = QtGui.QFont()
        font.setFamily("Segoe UI Light")
        font.setPointSize(14)
        self.comboBox_accountype.setFont(font)
        self.comboBox_accountype.setObjectName("comboBox_accountype")
        self.comboBox_accountype.addItem("")
        self.comboBox_accountype.addItem("")
        self.comboBox_accountype.addItem("")
        self.comboBox_accountype.addItem("")
        self.comboBox_accountype.addItem("")
        self.comboBox_accountype.addItem("")
        self.comboBox_accountype.addItem("")
        self.comboBox_accountype.addItem("")
        self.comboBox_accountype.setItemText(7, "")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.comboBox_accountype)
        self.other_acc_type = QtWidgets.QLineEdit(self.formGroupBox)
        self.other_acc_type.setText("")
        self.other_acc_type.setObjectName("other_acc_type")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.other_acc_type)
        self.label_2 = QtWidgets.QLabel(self.formGroupBox)
        self.other_acc_type.setPlaceholderText("Ignore This, If Specific Account Already Choosen Above.")
        font = QtGui.QFont()
        font.setFamily("Verdana")
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.label_2)
        self.save_userid = QtWidgets.QLineEdit(self.formGroupBox)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.save_userid.setFont(font)
        self.save_userid.setObjectName("save_userid")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.save_userid)
        self.label_3 = QtWidgets.QLabel(self.formGroupBox)
        font = QtGui.QFont()
        font.setFamily("Verdana")
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.LabelRole, self.label_3)
        self.save_userpwd = QtWidgets.QLineEdit(self.formGroupBox)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.save_userpwd.setFont(font)
        self.save_userpwd.setObjectName("save_userpwd")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.FieldRole, self.save_userpwd)
        self.label_5 = QtWidgets.QLabel(self.formGroupBox)
        self.label_5.setObjectName("label_5")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.label_5)
        self.label_4 = QtWidgets.QLabel(Dialog)
        self.label_4.setGeometry(QtCore.QRect(80, 80, 511, 51))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.line = QtWidgets.QFrame(Dialog)
        self.line.setGeometry(QtCore.QRect(50, 130, 531, 16))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.label_6 = QtWidgets.QLabel(Dialog)
        self.label_6.setGeometry(QtCore.QRect(180, 20, 301, 31))
        font = QtGui.QFont()
        font.setPointSize(13)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.line_2 = QtWidgets.QFrame(Dialog)
        self.line_2.setGeometry(QtCore.QRect(197, 60, 251, 20))
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.horizontalGroupBox = QtWidgets.QGroupBox(Dialog)
        self.horizontalGroupBox.setGeometry(QtCore.QRect(350, 390, 241, 80))
        self.horizontalGroupBox.setObjectName("horizontalGroupBox")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalGroupBox)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.press_savebtn = QtWidgets.QPushButton(self.horizontalGroupBox)
        self.press_savebtn.setObjectName("press_savebtn")
        self.horizontalLayout.addWidget(self.press_savebtn)
        self.close_savebox = QtWidgets.QPushButton(self.horizontalGroupBox)
        self.close_savebox.setObjectName("close_savebox")
        self.horizontalLayout.addWidget(self.close_savebox)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def closesb(self):
        SBDialog.close()

    def saveCredInfo(self):
        # SqlMgmt=DatabaseManagement(database_name)
        SqlMgmt.CreateTable()
        # .print(len(SqlMgmt.FetchData()))
        if len(SqlMgmt.FetchData()) == 0:
            # !no data so reset id to 0
            self.position = 0
        else:
            self.position = len(SqlMgmt.FetchData())
        print("will save by ID %s" % self.position)
        username_tosave = self.save_userid.text()
        self.save_userid.clear()
        password_tosave = self.save_userpwd.text()
        self.save_userpwd.clear()
        accounttype = self.comboBox_accountype.currentText()

        otherspecificacc = self.other_acc_type.text()
        self.other_acc_type.clear()
        if accounttype == 'Other':
            # !user should provide other name.
            if len(otherspecificacc) == 0:
                otherspecificacc = "Other"
            else:
                # !take user inputed account name.
                pass
            SqlMgmt.InsertNewDetails(self.position, otherspecificacc, username_tosave, password_tosave)

        elif accounttype != "Other":
            # !specific option found in list.
            SqlMgmt.InsertNewDetails(self.position, accounttype, username_tosave, password_tosave)
            pass

        # print(SqlMgmt.FetchData())
        SBDialog.close()
        # SqlMgmt.CloseConnections()

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Save Credentials"))
        self.label.setText(_translate("Dialog", "Account Type : "))
        self.comboBox_accountype.setItemText(0, _translate("Dialog", "Facebook"))
        self.comboBox_accountype.setItemText(1, _translate("Dialog", "Twitter"))
        self.comboBox_accountype.setItemText(2, _translate("Dialog", "Instagram"))
        self.comboBox_accountype.setItemText(3, _translate("Dialog", "Google"))
        self.comboBox_accountype.setItemText(4, _translate("Dialog", "Flipkart"))
        self.comboBox_accountype.setItemText(5, _translate("Dialog", "Amazon"))
        self.comboBox_accountype.setItemText(6, _translate("Dialog", "Other"))
        self.label_2.setText(_translate("Dialog", "UserID : "))
        self.label_3.setText(_translate("Dialog", "Password  : "))
        self.label_5.setText(_translate("Dialog", "Other Account Type: "))
        self.label_4.setText(_translate("Dialog", "Enter Your Account Type Along With Credentials To Save It To Vault"))
        self.label_6.setText(_translate("Dialog", "Hydrogen Password Manager"))
        self.press_savebtn.setText(_translate("Dialog", "Save Credentials"))
        self.close_savebox.setText(_translate("Dialog", "Cancel"))

        self.close_savebox.clicked.connect(self.closesb)
        self.press_savebtn.clicked.connect(self.saveCredInfo)


class Ui_PWManager(object):
    def setupUi(self, PWManager):
        PWManager.setObjectName("PWManager")
        PWManager.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        PWManager.resize(940, 480)
        self.table_widget = QtWidgets.QTableWidget(PWManager)
        self.table_widget.setGeometry(QtCore.QRect(50, 70, 511, 351))
        self.table_widget.setRowCount(100)
        self.table_widget.setColumnCount(4)
        self.table_widget.setObjectName("table_widget")
        self.table_widget.horizontalHeader().setVisible(True)
        self.table_widget.horizontalHeader().setCascadingSectionResizes(False)
        self.table_widget.verticalHeader().setVisible(False)
        self.table_widget.setHorizontalHeaderLabels(["Id", "Account Type", "UserID", "PassCode"])
        self.line = QtWidgets.QFrame(PWManager)
        self.line.setGeometry(QtCore.QRect(610, 60, 20, 371))
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.table_widget.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.label = QtWidgets.QLabel(PWManager)
        self.label.setGeometry(QtCore.QRect(660, 20, 341, 61))
        font = QtGui.QFont()
        font.setFamily("Segoe MDL2 Assets")
        font.setPointSize(9)
        font.setBold(False)
        font.setWeight(50)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.verticalFrame = QtWidgets.QFrame(PWManager)
        self.verticalFrame.setGeometry(QtCore.QRect(700, 170, 165, 261))
        self.verticalFrame.setObjectName("verticalFrame")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalFrame)
        self.verticalLayout.setObjectName("verticalLayout")
        self.add_account = QtWidgets.QPushButton(self.verticalFrame)
        self.add_account.setObjectName("add_account")
        self.verticalLayout.addWidget(self.add_account)
        self.update_account = QtWidgets.QPushButton(self.verticalFrame)
        self.update_account.setObjectName("update_account")
        self.verticalLayout.addWidget(self.update_account)
        self.delete_account = QtWidgets.QPushButton(self.verticalFrame)
        self.delete_account.setObjectName("delete_account")
        self.verticalLayout.addWidget(self.delete_account)
        self.delete_env = QtWidgets.QPushButton(self.verticalFrame)
        self.delete_env.setObjectName("delete_env")
        self.verticalLayout.addWidget(self.delete_env)
        self.line_2 = QtWidgets.QFrame(PWManager)
        self.line_2.setGeometry(QtCore.QRect(660, 160, 241, 20))
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.horizontalLayoutWidget = QtWidgets.QWidget(PWManager)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(660, 100, 241, 51))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")

        self.qTimer = QtCore.QTimer()
        self.qTimer.setInterval(2000)
        self.qTimer.timeout.connect(self.RefreshCredentials)
        self.qTimer.start()

        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.close_vault = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.close_vault.setObjectName("close_vault")
        self.horizontalLayout.addWidget(self.close_vault)
        self.line_4 = QtWidgets.QFrame(PWManager)
        self.line_4.setGeometry(QtCore.QRect(650, 80, 251, 20))
        self.line_4.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_4.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_4.setObjectName("line_4")
        self.programmer_banner = QtWidgets.QLabel(PWManager)
        self.programmer_banner.setGeometry(QtCore.QRect(80, 30, 381, 16))
        self.programmer_banner.setObjectName("programmer_banner")
        self.retranslateUi(PWManager)
        QtCore.QMetaObject.connectSlotsByName(PWManager)
        # self.table_widget.clearContents()
        self.RefreshCredentials()

    def ClosePWDManager(self):
        # print(mkey)
        DBSecurity = DatabaseAccess(mkey)
        SqlMgmt.CloseConnections()
        #DBSecurity.LockDatabase()  # !lock at the end.
        self.table_widget.clearContents()
        # SqlMgmt.CloseConnections()
        PWManager.close()
        DBEraser.RunEraser()

    def OpenSBManager(self):
        SBDialog.show()

    def DeleteAcc(self):
        DeleteFrm.show()

        pass

    def RefreshCredentials(self):
        global SqlMgmt
        # SqlMgmt = DatabaseManagement(database_name)
        if SqlMgmt.IsClose:
            SqlMgmt = DatabaseManagement(database_name)

        SqlMgmt.CreateTable()
        data = SqlMgmt.FetchData()
        if len(data) == 0:
            self.table_widget.clearContents()
        self.table_widget.clearContents()
        for rowno, rowdata in enumerate(data):
            for colno, coldata in enumerate(rowdata):
                self.table_widget.setItem(rowno, colno, QtWidgets.QTableWidgetItem(str(coldata)))

        # print("this is refresh")
        pass

    def DeleteBatch(self):
        global SqlMgmt
        data = SqlMgmt.FetchData()
        for rowno, rowdata in enumerate(data):
            for colno, coldata in enumerate(rowdata):
                self.table_widget.setItem(rowno, colno, QtWidgets.QTableWidgetItem(str("")))
        SqlMgmt.DeleteDatabase()
        SqlMgmt = DatabaseManagement(database_name)

    def DeleteEnvironment(self):
        SqlMgmt.CloseConnections()
        SqlMgmt.DeleteDatabase()
        sys_files = ['pmanager.key', 'Hydrogen.conf']
        for eachfile in sys_files:
            try:
                remove(eachfile)
                PWManager.close()
            except FileNotFoundError as msg:
                print(msg)
                print("unable to delete %s" % eachfile)
                pass

    def retranslateUi(self, PWManager):
        _translate = QtCore.QCoreApplication.translate
        PWManager.setWindowTitle(_translate("PWManager", "Hydrogen Password Manager"))
        self.label.setText(_translate("PWManager", "Hydrogen Personal Credentials Vault."))
        self.add_account.setText(_translate("PWManager", "Add Account"))
        self.update_account.setText(_translate("PWManager", "Clear Environment"))
        self.delete_account.setText(_translate("PWManager", "Delete Account"))
        self.delete_env.setText(_translate("PWManager", "Delete Environment"))
        self.close_vault.setText(_translate("PWManager", "Close Vault"))
        self.programmer_banner.setText(
            _translate("PWManager", "Written By : Tanmay Upadhyay (kevinthemetnik@gmail.com)"))
        self.close_vault.clicked.connect(self.ClosePWDManager)
        self.add_account.clicked.connect(self.OpenSBManager)
        self.update_account.clicked.connect(self.DeleteBatch)
        self.delete_account.clicked.connect(self.DeleteAcc)
        self.delete_env.clicked.connect(self.DeleteEnvironment)


class CHECKACCESS(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        Form.resize(666, 490)
        self.environment_creation_wizard = QtWidgets.QLabel(Form)
        self.environment_creation_wizard.setGeometry(QtCore.QRect(90, 20, 491, 51))
        font = QtGui.QFont()
        font.setFamily("Myanmar Text")
        font.setPointSize(12)
        self.environment_creation_wizard.setFont(font)
        self.environment_creation_wizard.setObjectName("environment_creation_wizard")
        self.line = QtWidgets.QFrame(Form)
        self.line.setGeometry(QtCore.QRect(90, 70, 421, 16))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setGeometry(QtCore.QRect(50, 60, 561, 71))
        self.label_2.setObjectName("label_2")
        self.Hydrogen_ID = QtWidgets.QLineEdit(Form)
        self.Hydrogen_ID.setGeometry(QtCore.QRect(320, 161, 201, 41))
        self.Hydrogen_ID.setStyleSheet("color:black\n"
                                       "")
        self.Hydrogen_ID.setText("")
        self.Hydrogen_ID.setObjectName("Hydrogen_ID")
        self.Hydrogen_Password = QtWidgets.QLineEdit(Form)
        self.Hydrogen_Password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.Hydrogen_Password.setGeometry(QtCore.QRect(320, 261, 201, 41))
        self.Hydrogen_Password.setStyleSheet("color:black")
        self.Hydrogen_Password.setObjectName("Hydrogen_Password")
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setGeometry(QtCore.QRect(60, 340, 571, 20))
        self.label_3.setText("")
        self.label_3.setObjectName("label_3")
        self.horizontalLayoutWidget = QtWidgets.QWidget(Form)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(179, 380, 271, 80))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.CreateSecureWizard = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.CreateSecureWizard.setObjectName("CreateSecureWizard")
        self.horizontalLayout.addWidget(self.CreateSecureWizard)
        self.CancelEnvWizard = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.CancelEnvWizard.setObjectName("CancelEnvWizard")
        self.horizontalLayout.addWidget(self.CancelEnvWizard)
        self.hydrogen_id_label = QtWidgets.QLabel(Form)
        self.hydrogen_id_label.setGeometry(QtCore.QRect(102, 170, 121, 20))
        self.hydrogen_id_label.setObjectName("hydrogen_id_label")
        self.Hydrogen_Pwd_label = QtWidgets.QLabel(Form)
        self.Hydrogen_Pwd_label.setGeometry(QtCore.QRect(90, 270, 161, 20))
        self.Hydrogen_Pwd_label.setObjectName("Hydrogen_Pwd_label")

        self.TriggerCheckAccess(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def CloseAccessCheck(self):
        AccessCheck.close()

    def AuthenticateAccess(self):
        global mkey
        # print("login button pressed.")
        self.input_hydrogenID = self.Hydrogen_ID.text()
        self.input_hydrogenPWD = self.Hydrogen_Password.text()
        self.Hydrogen_ID.clear()
        self.Hydrogen_Password.clear()

        # !Try To Access Stored Hashes.
        try:
            self.key_location = getenv('userprofile')
            chdir(self.key_location)
        except:
            # !maintain current directory.
            pass

        # print('Current Dir : %s'%getcwd())
        self.config = ""
        self.username_hash = ""
        self.password_hash = ""
        self.dummy = False
        # !will open configuration file to capture salt.
        try:
            with open(program_config, 'r') as config:
                self.config = config.readlines()
            with open("pmanager.key", 'r') as keys:
                self.keyfile = keys.readlines()
        except FileNotFoundError:
            # !if any of the core files are absent it will request user to create new environment.
            self.error_msgBox = QMessageBox()
            self.error_msgBox.setIcon(QMessageBox.Critical)
            self.error_msgBox.setText("No Valid Environment Found Relating To Provided Credentials, Please Create New.")
            self.error_msgBox.setWindowTitle("Environment Not Found")
            self.error_msgBox.setStandardButtons(QMessageBox.Ok)
            self.error_msgBox.show()
            AccessCheck.close()

        for eachline in self.config:
            eachline = eachline.replace("\n", "")
            if ">>" in eachline:
                mkey_ret = eachline.split(">>")[1]
                mkey = mkey_ret
                DBSecurity = DatabaseAccess(mkey)
                #DBSecurity.UnlockDatabase()  # !unlock before use.
            if "Environment:" in eachline:
                eachline = eachline.split("Environment:")[1]
                if "ALREADYSET" in eachline:
                    # !indication than master account already exists.
                    with open("pmanager.key", "r") as cred:
                        cred_data = cred.readlines()

                    for eachline in cred_data:
                        eachline = eachline.replace("\n", "")
                        if "[U]" in eachline:
                            # !to capture user hash
                            self.username_hash = eachline.split("[U]")[1]
                        elif "[P]" in eachline:
                            # !to capture password hash
                            self.password_hash = eachline.split("[P]")[1]

        # !now lets encrypt input credentials to match with captured hashes.
        self.salt = b'\xb2\xc8\xe3\x00\x04\x03\xc5P\x88\x13Z\x1f\x9c\xe5R8'
        self.udf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend())
        self.pdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend())
        self.input_hydrogenID = self.input_hydrogenID.encode()
        self.input_hydrogenPWD = self.input_hydrogenPWD.encode()
        Enc_InputID = base64.urlsafe_b64encode(self.udf.derive(self.input_hydrogenID)).decode()
        Enc_InputPWD = base64.urlsafe_b64encode(self.pdf.derive(self.input_hydrogenPWD)).decode()

        USERID_VERIFIED = False
        USERPWD_VERIFIED = False

        # !authentication check.
        if Enc_InputID == self.username_hash:
            # !userID matches.
            USERID_VERIFIED = True
            if Enc_InputPWD == self.password_hash:
                # !password also matches.
                USERPWD_VERIFIED = True
            else:
                USERPWD_VERIFIED = False
        else:
            # !userID not matches
            USERID_VERIFIED = False

        # print(USERID_VERIFIED,USERPWD_VERIFIED)
        if len(self.username_hash) == 0 and len(self.password_hash) == 0 and len(self.config) == 0:
            self.dummy = True

        if not USERID_VERIFIED or not USERPWD_VERIFIED:
            if self.dummy:
                pass
            else:
                self.error_msgBox = QMessageBox()
                self.error_msgBox.setIcon(QMessageBox.Critical)
                self.error_msgBox.setText(
                    "Invalid Request To Access Secure Environment Detected,\nPlease Enter Correct Credentials.")
                self.error_msgBox.setWindowTitle("Invalid Authentication Request")
                self.error_msgBox.setStandardButtons(QMessageBox.Ok)
                self.error_msgBox.show()

        elif USERID_VERIFIED and USERPWD_VERIFIED:
            # !user provide us correct login information.
            AccessCheck.close()
            PWManager.show()

    def TriggerCheckAccess(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Hydrogen Access Check "))
        self.environment_creation_wizard.setText(_translate("Form", "Hydrogen - Secure Environment Access Check."))
        self.label_2.setText(_translate("Form",
                                        "You Need To Provide The Master Credentials Which You Used For Creating Secure Environment."))
        self.CreateSecureWizard.setText(_translate("Form", "Access Enviroment"))
        self.CancelEnvWizard.setText(_translate("Form", "Cancel"))
        self.hydrogen_id_label.setText(_translate("Form", "Your Hydrogen ID : "))
        self.Hydrogen_Pwd_label.setText(_translate("Form", "Your Hydrogen Password : "))
        self.CancelEnvWizard.clicked.connect(self.CloseAccessCheck)
        self.CreateSecureWizard.clicked.connect(self.AuthenticateAccess)


class EnvCreationWizard(object):
    def setupUi(self, CreateWizardForm):
        CreateWizardForm.setObjectName("CreateWizardForm")
        CreateWizardForm.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        CreateWizardForm.resize(666, 490)
        self.environment_creation_wizard = QtWidgets.QLabel(CreateWizardForm)
        self.environment_creation_wizard.setGeometry(QtCore.QRect(90, 20, 491, 51))
        font = QtGui.QFont()
        font.setFamily("Myanmar Text")
        font.setPointSize(12)
        self.environment_creation_wizard.setFont(font)
        self.environment_creation_wizard.setObjectName("environment_creation_wizard")
        self.line = QtWidgets.QFrame(CreateWizardForm)
        self.line.setGeometry(QtCore.QRect(90, 70, 421, 16))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.label_2 = QtWidgets.QLabel(CreateWizardForm)
        self.label_2.setGeometry(QtCore.QRect(90, 70, 561, 71))
        self.label_2.setObjectName("label_2")
        self.Hydrogen_ID = QtWidgets.QLineEdit(CreateWizardForm)
        self.Hydrogen_ID.setGeometry(QtCore.QRect(320, 161, 201, 41))
        self.Hydrogen_ID.setStyleSheet("color:black\n"
                                       "")
        self.Hydrogen_ID.setText("")
        self.Hydrogen_ID.setObjectName("Hydrogen_ID")
        self.Hydrogen_Password = QtWidgets.QLineEdit(CreateWizardForm)
        self.Hydrogen_Password.setGeometry(QtCore.QRect(320, 261, 201, 41))
        self.Hydrogen_Password.setStyleSheet("color:black")
        self.Hydrogen_Password.setObjectName("Hydrogen_Password")
        self.label_3 = QtWidgets.QLabel(CreateWizardForm)
        self.label_3.setGeometry(QtCore.QRect(60, 340, 571, 20))
        self.label_3.setObjectName("label_3")
        self.horizontalLayoutWidget = QtWidgets.QWidget(CreateWizardForm)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(179, 380, 271, 80))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.CreateSecureWizard = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.CreateSecureWizard.setObjectName("CreateSecureWizard")
        self.horizontalLayout.addWidget(self.CreateSecureWizard)
        self.CancelEnvWizard = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.CancelEnvWizard.setObjectName("CancelEnvWizard")
        self.horizontalLayout.addWidget(self.CancelEnvWizard)
        self.hydrogen_id_label = QtWidgets.QLabel(CreateWizardForm)
        self.hydrogen_id_label.setGeometry(QtCore.QRect(102, 170, 121, 20))
        self.hydrogen_id_label.setObjectName("hydrogen_id_label")
        self.Hydrogen_Pwd_label = QtWidgets.QLabel(CreateWizardForm)
        self.Hydrogen_Pwd_label.setGeometry(QtCore.QRect(90, 270, 161, 20))
        self.Hydrogen_Pwd_label.setObjectName("Hydrogen_Pwd_label")

        self.TriggerCreationWizard(CreateWizardForm)
        QtCore.QMetaObject.connectSlotsByName(CreateWizardForm)

    def CloseCreationWizard(self):
        CreateWizardForm.close()

    def SaveHydrogenCredentials(self):
        # !This method will Encrypt Hydrogen Credentials.
        try:
            # !save credentials at user profile.
            self.userprofile_location = getenv('userprofile')
            chdir(self.userprofile_location)
        except:
            # !use currect location only.
            pass
        # remove(database_name)
        self.salt = b'\xb2\xc8\xe3\x00\x04\x03\xc5P\x88\x13Z\x1f\x9c\xe5R8'
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend())
        self.qdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend())
        user_ID = self.Hydrogen_ID.text().encode()
        Password = self.Hydrogen_Password.text().encode()
        self.Hydrogen_ID.clear()
        self.Hydrogen_Password.clear()
        Ukey = base64.urlsafe_b64encode(self.kdf.derive(user_ID))  # !username key is created.
        Ukey = b"[U]" + Ukey
        Pkey = base64.urlsafe_b64encode(self.qdf.derive(Password))  # ! password key is generated.
        Pkey = b"[P]" + Pkey
        mkey = Fernet.generate_key()
        mkey = b">>" + mkey
        with open('pmanager.key', 'wb') as keys:
            keys.write(Ukey)
            keys.write(b"\n-----------------------------------\n")
            keys.write(Pkey)
            keys.write(b"\n-----------------------------------\n")
        with open(program_config, 'wb') as writeconfig:
            writeconfig.write(b'Environment:ALREADYSET\n')
            writeconfig.write(mkey)
            DBSecurity = DatabaseAccess(mkey)

        self.msgBox = QMessageBox()
        self.msgBox.setIcon(QMessageBox.Information)
        self.msgBox.setText(
            "Secure Environment With Provided Credentials Created Successfully, Now You Can Start Using Password Manager.")
        self.msgBox.setWindowTitle("Sucess")
        self.msgBox.setStandardButtons(QMessageBox.Ok)
        self.msgBox.show()
        CreateWizardForm.close()
        SqlMgmt.CloseConnections()
        #DBSecurity.LockDatabase()  # !lock initially.

    def TriggerCreationWizard(self, CreateWizardForm):
        _translate = QtCore.QCoreApplication.translate
        CreateWizardForm.setWindowTitle(_translate("CreateWizardForm", "CreateWizardForm"))
        self.environment_creation_wizard.setText(
            _translate("CreateWizardForm", "Hydrogen - Secure Environment Creation Wizard."))
        self.label_2.setText(
            _translate("CreateWizardForm", "Secure Environement Is Nothing But A Kind Of Master Account \n"
                                           "Which Will Hold All Your Credentials Safetly."))
        self.label_3.setText(_translate("CreateWizardForm",
                                        "(Recommended To Choose Password Containing Alpha Numeric And Special Characters.)"))
        self.CreateSecureWizard.setText(_translate("CreateWizardForm", "Create Now"))
        self.CancelEnvWizard.setText(_translate("CreateWizardForm", "Cancel"))
        self.hydrogen_id_label.setText(_translate("CreateWizardForm", "New Hydrogen ID : "))
        self.Hydrogen_Pwd_label.setText(_translate("CreateWizardForm", "New Hydrogen Password : "))

        self.CancelEnvWizard.clicked.connect(self.CloseCreationWizard)
        self.CreateSecureWizard.clicked.connect(self.SaveHydrogenCredentials)


class About_Me(object):
    """
    This class provides code for About Me GUI.
    """

    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        Form.resize(640, 620)
        self.label = QtWidgets.QLabel(Form)
        self.label.setGeometry(QtCore.QRect(200, 20, 291, 71))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.line = QtWidgets.QFrame(Form)
        self.line.setGeometry(QtCore.QRect(87, 80, 461, 20))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.verticalLayoutWidget = QtWidgets.QWidget(Form)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(70, 150, 160, 211))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_2 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_2.addWidget(self.label_2)
        self.label_3 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_3.setObjectName("label_3")
        self.verticalLayout_2.addWidget(self.label_3)
        self.label_4 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_4.setObjectName("label_4")
        self.verticalLayout_2.addWidget(self.label_4)
        self.label_5 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_5.setObjectName("label_5")
        self.verticalLayout_2.addWidget(self.label_5)
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(Form)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(269, 149, 252, 211))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label_6 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_6.setObjectName("label_6")
        self.verticalLayout_3.addWidget(self.label_6, 0, QtCore.Qt.AlignHCenter)
        self.label_7 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_7.setObjectName("label_7")
        self.verticalLayout_3.addWidget(self.label_7, 0, QtCore.Qt.AlignHCenter)
        self.label_8 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_8.setObjectName("label_8")
        self.verticalLayout_3.addWidget(self.label_8, 0, QtCore.Qt.AlignHCenter)
        self.label_9 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_9.setObjectName("label_9")
        self.verticalLayout_3.addWidget(self.label_9, 0, QtCore.Qt.AlignHCenter)
        self.label_10 = QtWidgets.QLabel(Form)
        self.label_10.setGeometry(QtCore.QRect(100, 410, 461, 61))
        self.label_10.setObjectName("label_10")
        self.pushButton = QtWidgets.QPushButton(Form)
        self.pushButton.setGeometry(QtCore.QRect(240, 520, 93, 28))
        self.pushButton.setObjectName("pushButton")

        self.AboutMeTrigger(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def CloseAboutMe(self):
        Form.close()

    def AboutMeTrigger(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label.setText(_translate("Form", "About The Programmer"))
        self.label_2.setText(_translate("Form", "Written By : "))
        self.label_3.setText(_translate("Form", "Email : "))
        self.label_4.setText(_translate("Form", "Facebook : "))
        self.label_5.setText(_translate("Form", "Github : "))
        self.label_6.setText(_translate("Form", "Tanmay Upadhyay"))
        self.label_7.setText(_translate("Form", "kevinthemetnik@gmail.com"))
        self.label_8.setText(_translate("Form", "/tanmayupadhyay91"))
        self.label_9.setText(_translate("Form", "https://github.com/tanmay606"))
        self.label_10.setText(
            _translate("Form", "If you have any suggestions, criticism or want to stay connected with me\n"
                               "You can connect with me on facebook or other social media accounts."))
        self.pushButton.setText(_translate("Form", "Close Window"))
        self.pushButton.clicked.connect(self.CloseAboutMe)


class PasswordManagerControllers(object):
    # !This Will Hold The Slots Of Program.
    def ExitApplication(self):
        # print("exit signal received")
        MainWindow.close()  # !quit the whole program.

    def About_Programmer(self):
        # print("about programmer signal")
        Form.show()

    def CreateNewVault(self):
        # !this method will tackle signal for creating new vault to start storing passwords.
        try:
            # !Vault Already Exists.
            # !We Will Not Tackle This Situation Here.
            try:
                self.userprofile_location = getenv('userprofile')
                chdir(self.userprofile_location)
            except:
                # !on the same location.
                pass
            with open(program_config, 'r') as config:
                configuration = config.read()
            with open("pmanager.key", "r") as keyfile:
                credfile = keyfile.read()
            msgBox = QMessageBox(self.horizontalGroupBox)
            msgBox.setIcon(QMessageBox.Information)
            msgBox.setText("Environment Already Exists, Please Open Existing Secure Environment Using Credentials.")
            msgBox.setWindowTitle("Vault Already Exists")
            msgBox.setStandardButtons(QMessageBox.Ok)
            msgBox.show()

        except FileNotFoundError:
            # !It Means No Vault Exists
            # print("No Secure Environment Not Found, We Will Create One Now.")
            CreateWizardForm.show()
            pass


class PasswordManagerUI(threading.Thread, PasswordManagerControllers, EnvCreationWizard):
    def setupUi(self, MainWindow):
        threading.Thread.__init__(self)
        MainWindow.setObjectName("MainWindow")
        MainWindow.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        MainWindow.resize(640, 480)
        MainWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.MainProgramBanner = QtWidgets.QLabel(self.centralwidget)
        self.MainProgramBanner.setGeometry(QtCore.QRect(140, 0, 371, 71))
        font = QtGui.QFont()
        font.setFamily("Nirmala UI")
        font.setPointSize(16)
        self.MainProgramBanner.setFont(font)
        self.MainProgramBanner.setObjectName("MainProgramBanner")
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setGeometry(QtCore.QRect(130, 60, 341, 16))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(100, 80, 421, 16))
        self.label_2.setObjectName("label_2")
        self.horizontalGroupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.horizontalGroupBox.setGeometry(QtCore.QRect(120, 250, 361, 101))
        self.horizontalGroupBox.setObjectName("horizontalGroupBox")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalGroupBox)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.create_vault = QtWidgets.QPushButton(self.horizontalGroupBox)
        self.create_vault.setObjectName("create_vault")
        self.horizontalLayout.addWidget(self.create_vault)
        self.open_vault = QtWidgets.QPushButton(self.horizontalGroupBox)
        self.open_vault.setObjectName("open_vault")
        self.horizontalLayout.addWidget(self.open_vault)
        self.quit_application = QtWidgets.QPushButton(self.horizontalGroupBox)
        self.quit_application.setObjectName("quit_application")
        self.horizontalLayout.addWidget(self.quit_application)
        self.commandLinkButton = QtWidgets.QCommandLinkButton(self.centralwidget)
        self.commandLinkButton.setGeometry(QtCore.QRect(160, 410, 281, 48))

        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(7)
        font.setBold(True)
        font.setItalic(False)
        font.setUnderline(True)
        font.setWeight(75)
        font.setStrikeOut(False)
        self.commandLinkButton.setFont(font)
        self.commandLinkButton.setObjectName("commandLinkButton")
        self.AboutProgrammer = QtWidgets.QFrame(self.centralwidget)
        self.AboutProgrammer.setGeometry(QtCore.QRect(130, 410, 321, 20))
        self.AboutProgrammer.setFrameShape(QtWidgets.QFrame.HLine)
        self.AboutProgrammer.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.AboutProgrammer.setObjectName("AboutProgrammer")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(50, 200, 581, 61))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(50, 150, 491, 41))
        self.label_4.setObjectName("label_4")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.TriggerUI(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def TriggerUI(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Hydrogen Password Manager"))
        self.MainProgramBanner.setText(_translate("MainWindow", "Hydrogen Password Manager "))
        self.label_2.setText(
            _translate("MainWindow", "Simple And Secure Way To Manage All Your Credentials At One Place."))
        self.create_vault.setText(_translate("MainWindow", "Create New Vault"))
        self.open_vault.setText(_translate("MainWindow", "Manage Credentials"))
        self.quit_application.setText(_translate("MainWindow", "Quit"))
        self.commandLinkButton.setText(_translate("MainWindow", "Click here to know the Programmer."))
        self.label_3.setText(_translate("MainWindow",
                                        "If You Are Using This Program For The First Time Start By Creating New Vault To Create\n"
                                        "\t\t\tEncrypted Vault To Store All Your Details."))
        self.label_4.setText(_translate("MainWindow",
                                        "This Program Uses Strong Symmetric Encryption To Hold Your Sensitive Credentials."))
        self.ProgramSignals()

    def OpenVaultSystem(self):
        print("open vault signal ")
        AccessCheck.show()
        pass

    def ProgramSignals(self):
        # ! it will configure signals to be sended to slots.
        self.quit_application.clicked.connect(self.ExitApplication)
        self.create_vault.clicked.connect(self.CreateNewVault)
        self.open_vault.clicked.connect(self.OpenVaultSystem)
        self.commandLinkButton.clicked.connect(self.About_Programmer)


class Delete_DeleteFrm(object):
    def setupUi(self, DeleteFrm):
        DeleteFrm.setObjectName("DeleteFrm")
        DeleteFrm.resize(484, 298)
        self.horizontalFrame = QtWidgets.QFrame(DeleteFrm)
        self.horizontalFrame.setGeometry(QtCore.QRect(140, 80, 191, 80))
        self.horizontalFrame.setObjectName("horizontalFrame")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalFrame)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(self.horizontalFrame)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.delete_id = QtWidgets.QLineEdit(self.horizontalFrame)
        self.delete_id.setObjectName("delete_id")
        self.horizontalLayout.addWidget(self.delete_id)
        self.del_label = QtWidgets.QLabel(DeleteFrm)
        self.del_label.setGeometry(QtCore.QRect(90, 40, 471, 21))
        self.del_label.setObjectName("del_label")
        self.line = QtWidgets.QFrame(DeleteFrm)
        self.line.setGeometry(QtCore.QRect(20, 60, 461, 20))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.horizontalGroupBox_2 = QtWidgets.QGroupBox(DeleteFrm)
        self.horizontalGroupBox_2.setGeometry(QtCore.QRect(90, 170, 281, 80))
        self.horizontalGroupBox_2.setObjectName("horizontalGroupBox_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.horizontalGroupBox_2)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.yes_delete = QtWidgets.QPushButton(self.horizontalGroupBox_2)
        self.yes_delete.setObjectName("yes_delete")
        self.horizontalLayout_2.addWidget(self.yes_delete)
        self.no_delete = QtWidgets.QPushButton(self.horizontalGroupBox_2)
        self.no_delete.setObjectName("no_delete")
        self.horizontalLayout_2.addWidget(self.no_delete)

        self.retranslateUi(DeleteFrm)
        QtCore.QMetaObject.connectSlotsByName(DeleteFrm)

    def DeleteTargetId(self):
        self.targetID = self.delete_id.text()
        # SqlMgmt = DatabaseManagement(database_name)
        SqlMgmt.DeleteWholeRow(int(self.targetID))
        DeleteFrm.close()

    def CloseDeleteBox(self):
        DeleteFrm.close()

    def retranslateUi(self, DeleteFrm):
        _translate = QtCore.QCoreApplication.translate
        DeleteFrm.setWindowTitle(_translate("DeleteFrm", "Delete Credentials Wizard"))
        self.label.setText(_translate("DeleteFrm", "Target ID: "))
        self.del_label.setText(_translate("DeleteFrm", "Enter Target Account ID To Remove It From Database."))
        self.yes_delete.setText(_translate("DeleteFrm", " Delete Account"))
        self.no_delete.setText(_translate("DeleteFrm", "Cancel"))
        self.yes_delete.clicked.connect(self.DeleteTargetId)
        self.no_delete.clicked.connect(self.CloseDeleteBox)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ProgramUI = PasswordManagerUI()
    ProgramUI.setupUi(MainWindow)
    MainWindow.show()
    Form = QtWidgets.QWidget()
    ui = About_Me()
    ui.setupUi(Form)

    CreateWizardForm = QtWidgets.QWidget()
    CreationWizardUI = EnvCreationWizard()
    CreationWizardUI.setupUi(CreateWizardForm)

    AccessCheck = QtWidgets.QWidget()
    AccessCheckUI = CHECKACCESS()
    AccessCheckUI.setupUi(AccessCheck)

    PWManager = QtWidgets.QWidget()
    PWManagerUI = Ui_PWManager()
    PWManagerUI.setupUi(PWManager)

    SBDialog = QtWidgets.QDialog()
    SBui = SB_Dialog()
    SBui.setupUi(SBDialog)

    DeleteFrm = QtWidgets.QWidget()
    DeleteFrmUI = Delete_DeleteFrm()
    DeleteFrmUI.setupUi(DeleteFrm)

    sys.exit(app.exec_())
