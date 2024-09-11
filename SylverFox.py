from PySide6.QtWidgets import QApplication, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMainWindow, QWidget, QComboBox
from PySide6.QtGui import QIcon
import sys
import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from opcua import Server, ua

# Ask for info to generate a certificate
class CertParamDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Certificate Generation')
        self.setWindowIcon(QIcon('./Data/img/cert_ico.png'))
        name = organization = country = locality = ''

        layout = QVBoxLayout()
        
        self.name_label = QLabel('Your Name:')
        self.name_input = QLineEdit("SilverFox")
        self.name_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_input)

        self.organization_label = QLabel('Organization Name:')
        self.organization_input = QLineEdit()
        self.organization_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.organization_label)
        layout.addWidget(self.organization_input)

        self.country_label = QLabel('Country:')
        self.country_input = QLineEdit()
        self.country_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.country_label)
        layout.addWidget(self.country_input)

        self.locality_label = QLabel('Locality:')
        self.locality_input = QLineEdit()
        self.locality_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.locality_label)
        layout.addWidget(self.locality_input)

        self.ok_button = QPushButton('OK')
        self.ok_button.clicked.connect(self.accept)
        self.ok_button.setEnabled(False)
        layout.addWidget(self.ok_button)

        self.setLayout(layout)
        
        self.setWhatsThis("This dialog allows you to input parameters for certificate generation.")
        

    def get_parameters(self):
        name = self.name_input.text()
        organization = self.organization_input.text()
        country = self.country_input.text()
        locality = self.locality_input.text()
        return name, organization, country, locality
    
    def save_toggle(self):
        if self.name_input.text():
            if self.country_input.text():
                if len(self.country_input.text()) == 2:
                    self.ok_button.setEnabled(True)
                else:
                    self.ok_button.setEnabled(False)
            else:
                self.ok_button.setEnabled(True)
        else:
            self.ok_button.setEnabled(False)

# Manage the certificate, check if a RedBee certificate is present, if not generate a new one
class CertificateHandler:

    '''
    CertificateHandler

    Description:
    The CertificateHandler class is responsible for managing the certificate used by the application. 
    It checks if a RedBee certificate is present, and if not, it generates a new one.

    Responsibilities:
    Generate a RedBee certificate if one does not exist.
    Load the existing certificate and private key.
    Provide methods for certificate generation and initialization.
    Provide a user interface for entering the organization name for certificate generation.

    Attributes:
    cert_path: Path to the certificate file.
    private_key_path: Path to the private key file.
    certificate: Stores the certificate data.
    private_key: Stores the private key data.

    Interfaces:
    generate_certificate(organization): Generates a RedBee certificate with the specified organization name.
    initialize(): Initializes the certificate handler, loading the certificate and private key if they exist.
    cert_param_ui(): Provides a user interface for entering the organization name for certificate generation.
    '''

    def __init__(self):
        print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Initializing..")
        self.cert_path = './Client/pki/own/cert/cert.pem'
        self.private_key_path = './Client/pki/own/private/private_key.pem'
        self.certificate = None
        self.private_key = None
        self.initialize()
        print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Initialized!")
            
    def generate_certificate(self, name="SilverFox", organization="", country="", locality=""):
        print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Generating Certificate..")
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Create a certificate
        subject_name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
        issuer_name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
        if organization:
            subject_name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
            issuer_name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if country:
            subject_name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
            issuer_name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if locality:
            subject_name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
            issuer_name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name(subject_name_attributes))
        builder = builder.issuer_name(x509.Name(issuer_name_attributes))
        
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        # Add the dataEncipherment extension
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('your.domain.com')
            ]),
            critical=False,  # Adjust criticality based on your requirements
        )
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )
        
        # Serialize certificate and private key
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Write certificate in ./Client/pki/own/cert/certificate.pem
        with open('./Client/pki/own/cert/cert.pem', 'wb') as f:
            f.write(cert_pem)
        self.cert_path = './Client/pki/own/cert/cert.pem'
        # Write private key in ./Client/pki/own/private/private_key.pem
        with open('./Client/pki/own/private/private_key.pem', 'wb') as f:
            f.write(private_key_pem)
        self.private_key_path = './Client/pki/own/private/private_key.pem'
        print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Certificate and private key generated!")
        #return cert_pem, private_key_pem
        return certificate, private_key

    def initialize(self):
        if (not os.path.exists("./Client/pki/own/private/private_key.pem")) or (not os.path.exists("./Client/pki/own/cert/cert.pem")):
            try:
                os.makedirs("./Client/pki/own/private", exist_ok=True)
                os.makedirs("./Client/pki/own/cert", exist_ok=True)
                name, organization, country, locality = CertificateHandler.cert_param_ui()
            except Exception as e:
                print(str(e))
            else:
                self.certificate, self.private_key = self.generate_certificate(name, organization, country, locality)
                print("Certificate created!")
        else:
            with open(self.cert_path, 'rb') as f:
                self.certificate = x509.load_pem_x509_certificate(f.read())
            with open(self.private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Certificate and private key loaded!")
            
    def regenerate(self):
        try:
            name, organization, country, locality = CertificateHandler.cert_param_ui()
        except Exception as e:
            pass
        else:
            if not name and not organization and not country and not locality:
                pass
            else:
                self.certificate, self.private_key = self.generate_certificate(name, organization, country, locality)
        
    @staticmethod
    def cert_param_ui():
        name, organization, country, locality = "", "", "", ""
        try:
            cert_app = QApplication.instance()
            if not cert_app:
                cert_app = QApplication(sys.argv)
            dialog = CertParamDialog()
            if dialog.exec():
                name, organization, country, locality = dialog.get_parameters()
            return name, organization, country, locality
        except Exception as e:
            print("Error in CertParam_UI" + str(e))
            #ExceptionHandler.unhandled_exception(e, "CertParameter_UI")

# Configurable OPC UA Server
class OpcUaServer:
    def __init__(self):
        self.certificate_handler = CertificateHandler()
        self.certificate = self.certificate_handler.certificate
        self.private_key = self.certificate_handler.private_key
        self.server = Server()
        self.server.set_endpoint("opc.tcp://192.168.153.1:4840/SilverFox/")
        self.server.set_server_name("SylverFox")
        self.server.set_application_uri("http://opcfarm.org/UA/SilverFox/")
        self.server.register_namespace("urn:SilverFox:opcua:server")
        self.server.set_build_info("urn:SilverFox:opcua:server", "OPC Farm", "SilverFox", "1.0", "1", datetime.datetime.now())
        self.server.load_certificate(self.certificate_handler.cert_path)
        self.server.load_private_key(self.certificate_handler.private_key_path)
        self.server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
        #self.server.set_security_mode(ua.MessageSecurityMode.SignAndEncrypt)
        self.event_generator = self.server.get_event_generator()
        self.node_silverfox = self.create_node("ns=1;i=1", "SilverFox")

        print(f"OPC UA Server initialized with param: endpoint={self.server.endpoint}, cert_path={self.certificate_handler.cert_path}, private_key_path={self.certificate_handler.private_key_path}")
    
    def start(self):
        self.server.start()
        print("OPC UA Server started...")
    
    def stop(self):
        self.server.stop()
        print("OPC UA Server stopped.")

    def create_folder(self, folder_id, folder_name):
        return self.server.nodes.objects.add_folder(folder_id, folder_name)
        
    def create_node(self, node_id, node_name, node_type=None):
        return self.server.nodes.objects.add_object(node_id, node_name, node_type)
    
    def create_variable(self, node, variable_id, variable_name, variable_value, var_type=None, data_type=None):
        return node.add_variable(variable_id, variable_name, variable_value, var_type, data_type)
    
    def create_event(self, event_id, event_name, event_namespace):
        return self.event_generator.add_event(event_id, event_name, event_namespace)
    
    def trigger_event(self, event, event_data):
        event.trigger(event_data)
        
    def set_security_policy(self, security_policy):
        self.server.set_security_policy(security_policy)
        
    def set_security_mode(self, security_mode):
        self.server.set_security_mode(security_mode)
                
class InputDialog(QDialog):
    def __init__(self, prompt, parent=None):
        super().__init__(parent)
        self.setWindowTitle(prompt)
        self.layout = QVBoxLayout()
        self.input_line = QLineEdit(self)
        self.layout.addWidget(self.input_line)
        self.ok_button = QPushButton("OK", self)
        self.ok_button.clicked.connect(self.accept)
        self.layout.addWidget(self.ok_button)
        self.setLayout(self.layout)

    def get_input(self):
        return self.input_line.text()
    
class MultiInputDialog(QDialog):
    def __init__(self, prompts, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Input Required")
        self.layout = QVBoxLayout()
        self.inputs = []

        for prompt in prompts:
            label = QLabel(prompt)
            input_line = QLineEdit()
            self.layout.addWidget(label)
            self.layout.addWidget(input_line)
            self.inputs.append(input_line)

        self.ok_button = QPushButton("OK", self)
        self.ok_button.clicked.connect(self.accept)
        self.layout.addWidget(self.ok_button)
        self.setLayout(self.layout)

    def get_inputs(self):
        return [input_line.text() for input_line in self.inputs]

class ConfigDialog(QDialog):
    def __init__(self, server, parent=None):
        super().__init__(parent)
        self.server = server
        self.setWindowTitle("Configure Server")
        self.setWindowIcon(QIcon('./Data/img/config_ico.png'))
        self.layout = QVBoxLayout()

        self.create_node_button = QPushButton("Create Node")
        self.create_node_button.clicked.connect(self.create_node)
        self.layout.addWidget(self.create_node_button)

        self.create_variable_button = QPushButton("Create Variable")
        self.create_variable_button.clicked.connect(self.create_variable)
        self.layout.addWidget(self.create_variable_button)

        self.create_event_button = QPushButton("Create Event")
        self.create_event_button.clicked.connect(self.create_event)
        self.layout.addWidget(self.create_event_button)

        self.create_folder_button = QPushButton("Create Folder")
        self.create_folder_button.clicked.connect(self.create_folder)
        self.layout.addWidget(self.create_folder_button)

        self.setLayout(self.layout)

    def create_folder(self):
        dialog = MultiInputDialog(["Enter Folder Name", "Enter Folder ID"])
        if dialog.exec():
            
            folder_name, folder_id = dialog.get_input()
            if folder_id:
                self.server.create_folder(folder_id, folder_name)
            else:
                self.server.create_folder("ns=1;s=" + folder_name, folder_name)
            print(f"Folder '{folder_name}' created")


    def create_node(self):
        dialog = MultiInputDialog(["Enter Node ID", "Enter Node Name"])
        if dialog.exec():
            node_id, node_name = dialog.get_inputs()
            self.server.create_node(node_id, node_name)
            print(f"Node '{node_name}' with ID '{node_id}' created")

    def create_variable(self):
        dialog = MultiInputDialog(["Enter Variable ID", "Enter Variable Name", "Enter Initial Value"])
        if dialog.exec():
            variable_id, variable_name, variable_value = dialog.get_inputs()
            node = self.server.node_silverfox
            self.server.create_variable(node, variable_id, variable_name, variable_value)
            print(f"Variable '{variable_name}' with ID '{variable_id}' created")

    def create_event(self):
        dialog = MultiInputDialog(["Enter Event ID", "Enter Event Name", "Enter Event Namespace"])
        if dialog.exec():
            event_id, event_name, event_namespace = dialog.get_inputs()
            self.server.create_event(event_id, event_name, int(event_namespace))
            print(f"Event '{event_name}' with ID '{event_id}' created")

class SecuritySettingsWindow(QDialog):
    def __init__(self, server, parent=None):
        super(SecuritySettingsWindow, self).__init__(parent)
        self.server = server
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Security Settings')
        
        layout = QVBoxLayout()
        self.security_mode = QComboBox(self)
        self.security_mode.addItems(["None", "SignAndEncrypt"])#, "Sign", "SignAndEncrypt"])
        self.security_mode.currentIndexChanged.connect(self.toggle_settings)
        self.security_policy = QComboBox(self)
        self.security_policy.addItem("None")
        #self.security_policy.addItem("Basic256")
        #self.security_policy.addItem("Basic128Rsa15")
        self.security_policy.addItem("Basic256Sha256")
        self.security_policy.currentIndexChanged.connect(self.toggle_settings)

        layout.addWidget(self.security_mode)
        layout.addWidget(self.security_policy)
        self.applyButton = QPushButton('Apply', self)
        self.applyButton.clicked.connect(self.apply_security_settings)
        layout.addWidget(self.applyButton)
        self.setLayout(layout)
        self.toggle_settings()

    def apply_security_settings(self):
        # Retrieve the text of the selected items
        mode = self.security_mode.currentText()
        policy = self.security_policy.currentText()
        
        # Construct the attribute name
        attribute_name = f"{policy}_{mode}"
        
        # Access the corresponding attribute of the ua.SecurityPolicyType class
        try:
            security_policy_type = getattr(ua.SecurityPolicyType, attribute_name)
            # Apply the security policy
            self.server.server.set_security_policy([security_policy_type])
            print(f"Security Mode: {mode}, Security Policy: {policy}")
            self.accept()
        except AttributeError:
            print(f"Invalid security policy: {attribute_name}")
            # Handle invalid security policy selection if needed
        
    def toggle_settings(self):
        mode = self.security_mode.currentText()
        if mode == "None":
            self.security_policy.setCurrentIndex(0)
            self.security_policy.setEnabled(False)
        else:
            self.security_policy.setEnabled(True)
            if self.security_policy.currentIndex() == 0:
                self.security_policy.setCurrentIndex(1) 
            
            


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()


    def initUI(self):
        self.setWindowTitle("OPC UA Server Management")
        self.setWindowIcon(QIcon('./Data/img/server_ico.png'))
        self.server = OpcUaServer()

        self.central_widget = QWidget()
        self.layout = QVBoxLayout()

        self.start_button = QPushButton("Start Server")
        self.start_button.clicked.connect(self.start_server)
        self.layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Server")
        self.stop_button.clicked.connect(self.stop_server)
        self.layout.addWidget(self.stop_button)
        
        self.server_security_button = QPushButton('Server Security', self)
        self.server_security_button.clicked.connect(self.openSecuritySettings)
        self.layout.addWidget(self.server_security_button)

        self.configure_button = QPushButton("Configure Server")
        self.configure_button.clicked.connect(self.open_config_dialog)
        self.layout.addWidget(self.configure_button)

        self.central_widget.setLayout(self.layout)
        self.setCentralWidget(self.central_widget)

    def start_server(self):
        self.server.start()
        print("Server started")

    def stop_server(self):
        self.server.stop()
        print("Server stopped")

    def open_config_dialog(self):
        dialog = ConfigDialog(self.server)
        dialog.exec()
        
    def openSecuritySettings(self):
        self.securitySettingsWindow = SecuritySettingsWindow(self.server, self)
        self.securitySettingsWindow.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())