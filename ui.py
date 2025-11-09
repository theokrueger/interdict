import sys
import yaml
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QFormLayout, QFileDialog, QListWidget, QInputDialog

class ConfigEditor(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("YAML Configuration Editor")
        self.setGeometry(100, 100, 400, 350)

        # Layout
        self.layout = QVBoxLayout()

        # Form Layout for text boxes and labels
        self.form_layout = QFormLayout()

        # Labels and QLineEdits for the 2 numeric fields
        self.field1 = QLineEdit()
        self.field2 = QLineEdit()

        # Add labels and fields to the form layout
        self.form_layout.addRow("Delay Time (Number):", self.field1)
        self.form_layout.addRow("Aggressiveness (Number):", self.field2)

        # Blocklist UI (using QListWidget for the list of strings)
        self.blocklist_label = QLabel("Blocklist (URLs):")
        self.blocklist_list = QListWidget()

        # Instructions for adding URLs
        self.blocklist_instructions = QLabel("Add URLs to the blocklist below:")

        # Buttons for adding and removing blocklist items
        self.add_block_button = QPushButton("Add URL to Blocklist")
        self.remove_block_button = QPushButton("Remove Selected URL")

        # Connect buttons to functions
        self.add_block_button.clicked.connect(self.add_to_blocklist)
        self.remove_block_button.clicked.connect(self.remove_from_blocklist)

        # Add buttons and list to layout
        self.layout.addLayout(self.form_layout)
        self.layout.addWidget(self.blocklist_instructions)
        self.layout.addWidget(self.blocklist_label)
        self.layout.addWidget(self.blocklist_list)
        self.layout.addWidget(self.add_block_button)
        self.layout.addWidget(self.remove_block_button)

        # Load and Save Buttons
        self.save_button = QPushButton("Save YAML")
        
        self.save_button.clicked.connect(self.save_yaml)

        self.layout.addWidget(self.save_button)

        self.load_yaml()

        # Set layout for the window
        self.setLayout(self.layout)

    def load_yaml(self):
        """Load YAML configuration file and display values in text fields"""
        with open("config.yaml", 'r') as f:
            config = yaml.safe_load(f)

        # Populate fields with the loaded configuration, handling number fields
        self.field1.setText(str(config.get('delayTime', '')))
        self.field2.setText(str(config.get('aggressivness', '')))
        
        # Populate blocklist (list of strings)
        self.blocklist_list.clear()
        blocklist = config.get('blocklist', [])
        self.blocklist_list.addItems(blocklist)

    def save_yaml(self):
        """Save the current values in the text fields to the YAML file"""
        # Create config dictionary with data from UI
        config = {
            'delayTime': self.text_to_number(self.field1.text()),
            'aggressivness': self.text_to_number(self.field2.text()),
            'blocklist': [self.blocklist_list.item(i).text() for i in range(self.blocklist_list.count())]  # List of strings
        }
        with open("config.yaml", 'w') as f:
            yaml.dump(config, f, default_flow_style=False)

    def text_to_number(self, text: str):
        """Convert text to number (either int or float) if possible."""
        try:
            # Try converting to integer first
            return int(text)
        except ValueError:
            try:
                # If it fails, try converting to float
                return float(text)
            except ValueError:
                # If it can't be converted, return the original string
                return text

    def add_to_blocklist(self):
        """Add a URL to the blocklist"""
        url, ok = QInputDialog.getText(self, "Enter URL", "Add URL to Blocklist:")
        if ok and url:  # Proceed if the user entered a URL and clicked OK
            self.blocklist_list.addItem(url)

    def remove_from_blocklist(self):
        """Remove selected URL from the blocklist"""
        selected_items = self.blocklist_list.selectedItems()
        for item in selected_items:
            self.blocklist_list.takeItem(self.blocklist_list.row(item))

# Run the application
def main():
    app = QApplication(sys.argv)
    editor = ConfigEditor()
    editor.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

