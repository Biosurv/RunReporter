# IMPORTS
import sys, os, logging
from logging.handlers import RotatingFileHandler
import pandas as pd
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QFont, QIcon, QClipboard
from PyQt5.QtWidgets import QApplication, QMainWindow, QListWidget, QLineEdit, QPushButton, QMessageBox, QLabel, QFileDialog, QPlainTextEdit, QComboBox

# AUTHOR - Shean Mobed
# ORG - Biosurv International


# DESCRIPTION
"""
This App takes the final detailed run reports made by the Piranha pipeline, https://github.com/polio-nanopore/piranha, a makes a simple HTML report of all the results. 
It can process many reports at a time, and will list the runs present in the report.
Information presented per run:
- tally of the results based on Direct Detection Nanopore Sequencing (DDNS) of Poliovirus Method classification.
- list out the sample ID and EPID of VDPV samples as well assigned emergence group. 
- list Piranha and Minknow Software versions used in data generation
- display message if Run has failed QC
"""

# Compile Command - in commandprompt
"""
WINDOWS
nuitka --onefile --enable-plugins=pyqt5 --include-data-dir=assets=./assets --disable-console --windows-icon-from-ico=assets/Icon.ico --company-name="Biosurv International" --product-name="Run Reporter" --file-version=1.5.4 --file-description=="This App generates the contents of the email and a HTML report for DDNS/Isolate testing runs"  run_reporter.py
"""

# CHANGELOG 
"""
 V1.5.4 --> V1.5.5
- Added support for XLSX files, now can read both XLSX and CSV files
"""
version = '1.5.5'

def setup_logging(log_path=None):
    """Set up logging with a rotating file handler."""
    if log_path is None:
        log_path = os.path.join(os.getcwd(), 'app_error.log')
    else:
        log_path = os.path.join(log_path, 'app_error.log')
    
    try:
        handler = RotatingFileHandler(log_path, maxBytes=1000000, backupCount=5)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger = logging.getLogger('')
        logger.setLevel(logging.ERROR)
        logger.handlers = []  # Clear existing handlers
        logger.addHandler(handler)
        return log_path
    except PermissionError:
        logging.error(f"Permission denied writing log to {log_path}", exc_info=True)
        return os.path.join(os.getcwd(), 'app_error.log')

# Initial logging setup
current_log_path = setup_logging()
logging.error(f"Starting Run Reporter version {version}")

class ErrorHandler:
    """Redirect stderr to log errors."""
    def __init__(self):
        self.original_stderr = sys.stderr

    def write(self, message):
        self.original_stderr.write(message)
        if message.strip():
            logging.error(message.strip())

    def flush(self):
        self.original_stderr.flush()

def exception_hook(exctype, value, traceback):
    """Custom exception hook to log unhandled exceptions."""
    logging.error('Unhandled exception', exc_info=(exctype, value, traceback))
    app = QApplication.instance()
    msg = CustomMessageBox("warning", "An unhandled error occurred. Please check the log file (app_error.log) in the output destination for details.")
    msg.exec_()
    sys.__excepthook__(exctype, value, traceback)
    
class CustomMessageBox(QMessageBox):
    """Custom styled message box for warnings and information."""
    def __init__(self, type, message):
        super().__init__()
        self.setWindowTitle(type.capitalize())
        self.setText(message)
        self.setStandardButtons(QMessageBox.Ok)
        warning_style = """
            QMessageBox {background-color: white;color: black;}
            QMessageBox QLabel {color: black;}
            QMessageBox QPushButton {background-color: #ff9800; color: white;padding: 5px;border-radius: 3px; min-width: 80px; margin-left: auto; margin-right: auto;}
            QMessageBox QPushButton:hover {background-color: #e68900;}
        """
        information_style = """
            QMessageBox {background-color: white; color: black;}
            QMessageBox QLabel {color: black;}
            QMessageBox QPushButton {background-color: #2196F3; color: white;padding: 5px;border-radius: 3px; min-width: 80px; margin-left: auto; margin-right: auto;}
            QMessageBox QPushButton:hover {background-color: #1e87d9;}
        """
        self.setStyleSheet(warning_style if type.lower() == "warning" else information_style)

# APP
class ListBoxWidget(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.resize(500, 500)


    def dragEnterEvent(self, event):
        bg_label.hide()
        allowed_extensions = ('.csv', '.xlsx')
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if all(url.toLocalFile().lower().endswith(allowed_extensions) for url in urls):
                event.accept()
            else:
                event.ignore()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        #self.clear()
        allowed_extensions = ('.csv', '.xlsx')
        urls = event.mimeData().urls()
        file_paths = [url.toLocalFile() for url in urls if url.toLocalFile().lower().endswith(allowed_extensions)]
        self.addItems(file_paths)

        bg_label.setText('')


class App(QMainWindow):
    def __init__(self):
        super().__init__()

        screen_size = self.screen().size()
        screen_width = int(screen_size.width() * 0.5)
        screen_height = int(screen_size.height() * 0.8)
        self.resize(screen_width, screen_height)  # 1200,1000 original

        self.setStyleSheet("background-color: white; color: black;")  # Set window color to white

        self.setWindowIcon(
            QIcon(os.path.join(os.path.dirname(__file__), "assets/Icon.ico")))  # Sets top left icon to custom icon
        self.setWindowTitle("Run Reporter")  # App Title

        # ---- LOGO ----
        self.logo_label = QLabel(self)
        self.logo_label.setGeometry(int(screen_width * 0.03), int(screen_height * 0.03),
                                    int(screen_width * 0.1), int(screen_height * 0.1))  # Logo position x/y and dimension x/y
        pixmap = QPixmap(os.path.join(os.path.dirname(__file__), 'assets/Logo.png'))
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setScaledContents(True)
        
        # ---- TITLE ----
        self.title = QLabel('Run Reporter', self)
        self.title.setStyleSheet("background-color:transparent")
        self.title.setGeometry(int(screen_width * 0.4), int(screen_height * 0.08),
                                    int(screen_width * 0.25), int(screen_height * 0.05))
        self.title.setFont(QFont('Arial', 18))
        
        # ---- VERSION ----
        self.version_label = QLabel(f'Version: {version}', self)
        self.version_label.setStyleSheet("background-color:transparent")
        self.version_label.setGeometry(int(screen_width * 0.8), int(screen_height * 0.16),
                                    int(screen_width * 0.2), int(screen_height * 0.02))
        self.version_label.setFont(QFont('Arial', 9))
        
        # ---- MODE ----
        self.mode = QComboBox(self)
        self.mode.addItems(["DDNS","Isolate"])
        self.mode.setGeometry(int(screen_width * 0.13), int(screen_height * 0.15),
                              int(screen_width * 0.1), int(screen_height * 0.04))
        
        self.mode_label = QLabel('Mode:', self)
        self.mode_label.setStyleSheet("background-color:transparent")
        self.mode_label.setGeometry(int(screen_width * 0.05), int(screen_height * 0.16),
                                    int(screen_width * 0.1), int(screen_height * 0.02))
        self.mode_label.setFont(QFont('Arial', 9))

        # ---- DROPBOX ----
        self.listbox_view = ListBoxWidget(self)
        self.listbox_view.setStyleSheet("background-color:#FAF9F6;border-color:lightgrey;border-style: "
                                        "dashed;border-width: 2px;border-radius: 10px;")

        self.listbox_view.setGeometry(int(screen_width * 0.13), int(screen_height * 0.2),
                                      int(screen_width * 0.8), int(screen_height * 0.1))

        self.listbox_label = QLabel('Dropbox:', self)
        self.listbox_label.setStyleSheet("background-color:transparent")
        self.listbox_label.setGeometry(int(screen_width * 0.05), int(screen_height * 0.24),
                                       int(screen_width * 0.2), int(screen_height * 0.02))
        self.listbox_label.setFont(QFont('Arial', 9))

        global bg_label # set to global scope so it can be changed in various other app functions
        bg_label = QLabel('Drop CSV or XLSX files here', self)
        bg_label.setStyleSheet("background-color:#FAF9F6")
        bg_label.setGeometry(int(screen_width * 0.5), int(screen_height * 0.23),
                             int(screen_width * 0.2), int(screen_height * 0.05))
        
        # ---- DESTINATION BOX ----
        self.destination_entry = QLineEdit(self)
        self.destination_entry.setStyleSheet("background-color:#FAF9F6;border-color:lightgrey;border-style: "
                                             "dashed;border-width: 2px;border-radius: 10px;")
        self.destination_entry.setGeometry(int(screen_width * 0.13), int(screen_height * 0.32),
                                           int(screen_width * 0.8), int(screen_height * 0.06))
        self.destination_entry.setFont(QFont('Arial', 11))
        #self.destination_entry.setText('C:/Users/SheanMobed/OneDrive - Biosurv International/Desktop')

        self.destination_label = QLabel('Destination:', self)
        self.destination_label.setStyleSheet("background-color:transparent")
        self.destination_label.setGeometry(int(screen_width * 0.03), int(screen_height * 0.325),
                                           int(screen_width * 0.2), int(screen_height * 0.05))
        self.destination_label.setFont(QFont('Arial', 9))
        
        # ---- TEXTBOX ----
        self.textbox = QPlainTextEdit(self)
        self.textbox.setGeometry(int(screen_width * 0.13), int(screen_height * 0.4),
                                 int(screen_width * 0.8), int(screen_height * 0.47))

        self.textbox_label = QLabel('Report:', self)
        self.textbox_label.setStyleSheet("background-color:transparent")
        self.textbox_label.setGeometry(int(screen_width * 0.05), int(screen_height * 0.58),
                                       int(screen_width * 0.2), int(screen_height * 0.05))
        self.textbox_label.setFont(QFont('Arial', 9))

        # ---- BUTTONS ----        
        self.btn_save = QPushButton('Generate Report', self)
        self.btn_save.setGeometry(int(screen_width * 0.15), int(screen_height * 0.9),
                                  int(screen_width * 0.15), int(screen_height * 0.07))  
        self.btn_save.setFont(QFont('Arial', 9))
        self.btn_save.setStyleSheet("QPushButton{color: black; border-radius: 15px;background-color:#f7ae6c;border-color:black;border-style: solid;border-width: 1px;}"
                                    "QPushButton::pressed{background-color : #fce0b0;}")
        self.btn_save.clicked.connect(self.parse_csv)
        
        # User defined file destination
        self.destination_btn = QPushButton('Destination', self)
        self.destination_btn.setGeometry(int(screen_width * 0.35), int(screen_height * 0.9), int(screen_width * 0.15), int(screen_height * 0.07))  # 750, 770, 300, 100
        self.destination_btn.setFont(QFont('Arial', 9))
        self.destination_btn.setStyleSheet("QPushButton{color: black; border-radius: 15px;background-color:#f7ae6c;border-color:black;border-style: solid;border-width: 1px;}"
                                    "QPushButton::pressed{background-color : #fce0b0;}")
        self.destination_btn.clicked.connect(lambda: self.select_destination(3))
        
        self.btn_clear = QPushButton('Clear', self)
        self.btn_clear.setGeometry(int(screen_width * 0.55), int(screen_height * 0.9), int(screen_width * 0.15),
                                   int(screen_height * 0.07))  
        self.btn_clear.setFont(QFont('Arial', 9))
        self.btn_clear.setStyleSheet("QPushButton{color: black; border-radius: 15px;background-color:#f7ae6c;border-color:black;border-style: solid;border-width: 1px;}"
                                    "QPushButton::pressed{background-color : #fce0b0;}")
        self.btn_clear.clicked.connect(self.clear_list)

        self.btn_copy = QPushButton('Copy', self)
        self.btn_copy.setGeometry(int(screen_width * 0.75), int(screen_height * 0.9), int(screen_width * 0.15),
                                   int(screen_height * 0.07))  
        self.btn_copy.setFont(QFont('Arial', 9))
        self.btn_copy.setStyleSheet("QPushButton{color: black; border-radius: 15px;background-color:#f7ae6c;border-color:black;border-style: solid;border-width: 1px;}"
                                    "QPushButton::pressed{background-color : #fce0b0;}")
        self.btn_copy.clicked.connect(self.copy_text_to_clipboard)
        
    def select_destination(self, type):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.AnyFile if type in (1, 2) else QFileDialog.Directory)
        
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                if type == 1:
                    self.epi_entry.setText(selected_files[0])
                    self.listbox_view.addItem(selected_files[0])
                    bg_label.hide()

                elif type == 2:
                    self.lab_entry.setText(selected_files[0])
                    self.listbox_view.addItem(selected_files[0])
                    bg_label.hide()

                elif type == 3:
                    self.destination_entry.setText(selected_files[0])


    def copy_text_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.textbox.toPlainText(), QClipboard.Clipboard)
        
                    
    def parse_csv(self):
        paths = set(self.listbox_view.item(i).text() for i in range(self.listbox_view.count()))
        paths = sorted(paths)
        
        destination_path = self.destination_entry.text()
        
        if destination_path == '':
            QMessageBox.warning(self, 'Warning', 'No destination selected')
            return
            
        text = ''
        html = "<!DOCTYPE html><html><head>"  
         
        report_name_list = []
        ddns_total_pass = pd.DataFrame(columns=['classification'])
        ddns_total_sample_fail = pd.DataFrame(columns=['classification'])
        ddns_total_run_fail = pd.DataFrame(columns=['classification'])

        minknow_ver = 'missing'
        piranha_ver = 'missing'
        
        report_mode = self.mode.currentText()
        if report_mode == 'DDNS':
            essential_cols = ['sample','DDNSclassification','EpidNumber','RunQC','SampleQC','ToReport',
                            'AnalysisPipelineVersion','MinKNOWSoftwareVersion',
                            'Sabin1-related|classification','Sabin1-related|nt_diff_from_reference',
                            'Sabin2-related|classification','Sabin2-related|nt_diff_from_reference',
                            'Sabin3-related|classification','Sabin3-related|nt_diff_from_reference']
        else:
            essential_cols = ['sample','IsolateClassification','EpidNumber','RunQC','SampleQC','ToReport',
                'AnalysisPipelineVersion','MinKNOWSoftwareVersion',
                'Sabin1-related|classification','Sabin1-related|nt_diff_from_reference',
                'Sabin2-related|classification','Sabin2-related|nt_diff_from_reference',
                'Sabin3-related|classification','Sabin3-related|nt_diff_from_reference']
        
        # Removed because of new samples csv format, will leave here in case
        # 'EmergenceGroupVDPV1','EmergenceGroupVDPV2','EmergenceGroupVDPV3',

        col_rename_dict = {
        'DDNSclassification':'classification',
        'IsolateClassification':'classification'}

        for path in paths:
            report_name = path.rsplit('/')[-1].rsplit('_',3)[0]
            report_name_list.append(report_name)
            print(report_name)
            
            try:
                if path.endswith('.csv'):
                    report = pd.read_csv(path, sep=None, engine='python')
                else:
                    report = pd.read_excel(path)
                
            except pd.errors.ParserError as e:
                print(e)
                line_error = str(e).split('.')[0]
                if path.endswith('.csv'):
                    QMessageBox.warning(self, 'Warning', f'Error reading {report_name} CSV file, {line_error}')
                else:
                    QMessageBox.warning(self, 'Warning', f'Error reading {report_name} XLSX file, {line_error}')
                continue
            
            print('REPORT HEAD')
            print(report.head())
            # print(report.columns)
            
            if report.empty:
                print(f'Report: {report_name} has been read in as an empty dataframe')
                continue
            
            text += f'\nFor run: {report_name}, these results were found:\n'
            html += f'\n<h3>For run: <b><mark>{report_name}</mark></b>, these results were found:</h3>\n'
            
            vdpv_found = False
            sabin_found = False

            # Column presence check
            missing_cols = []
            for _ in essential_cols:
                if not _ in report.columns:
                    missing_cols.append(_)
                    
            # Rename classification columns
            report.rename(columns=col_rename_dict, inplace=True)
            
            if len(missing_cols) == 1:         
                QMessageBox.warning(self, 'Warning', f'Column: {missing_cols[0]} missing from report, please use correct report format')
                self.listbox_view.clear()
                return
            elif len(missing_cols) > 1:
                missing_cols = str(missing_cols).replace('[','').replace(']','').replace("'","")
                QMessageBox.warning(self, 'Warning', f'Columns:\n{missing_cols} are missing from {report_name}, please use correct report format')
                self.listbox_view.clear()
                return
            
            # set to int
            report['NonPolioEV|num_reads'] = pd.to_numeric(report['NonPolioEV|num_reads'], errors='coerce').astype('Int64')
            report['PositiveControl|num_reads'] = pd.to_numeric(report['PositiveControl|num_reads'], errors='coerce').astype('Int64')

            # Create masks for failure conditions based on CP and CN samples
            fail_CP_negative = (report['sample'].str.startswith("CP") & (report['NonPolioEV|num_reads'] < 50) & (report['PositiveControl|num_reads'] < 50))
            fail_CP_contaminated = report['sample'].str.startswith("CP") & ((report['Sabin1-related|num_reads'] > 50) | (report['Sabin2-related|num_reads'] > 50) | (report['Sabin3-related|num_reads'] > 50))
            fail_CN_contaminated = report['sample'].str.startswith("CN") & ((report['Sabin1-related|num_reads'] > 50) | (report['Sabin2-related|num_reads'] > 50) | (report['Sabin3-related|num_reads'] > 50))

            # If any sample meets failure criteria, mark the entire DataFrame as 'Fail'
            if fail_CP_negative.any():
                print("Negative Positive Control")
                text += 'This run has failed its RunQC, due to a Negative Positive Control\n'
                html += '<p><b><mark>This run has failed its RunQC, due to a Negative Positive Control</mark></b></p>\n'
                report['RunQC'] = 'Fail'
                
            elif fail_CP_contaminated.any():
                text += 'This run has failed its RunQC, due to a Contaminated Positive Control\n'
                html += '<p><b><mark>This run has failed its RunQC, due to a Contaminated Positive Control</mark></b></p>\n'
                report['RunQC'] = 'Fail'
                
            elif fail_CN_contaminated.any():
                text += 'This run has failed its RunQC, due to a Contaminated Negative Control\n'
                html += '<p><b><mark>This run has failed its RunQC, due to a Contaminated Negative Control</mark></b></p>\n'
                report['RunQC'] = 'Fail'
                
            # Run not processed if RunQC failed and adds message to report, set sampleQC to Fail for counts
            elif 'Fail' in report['RunQC'].values:
                print('RunQC Fail')
                report['SampleQC'] = 'Fail'
            
            # filter off envs for different processing
            envs = report.loc[report['sample'].str.match(r'^ENV-[A-Z]{3}[/-]\d{2}[/-]\d{3,5}$')]
            # Remove controls from df using regex
            report = report.loc[report['sample'].str.match(r'^[A-Z]{3}[/-]\d{2}[/-]\d{3,5}$')]
            
            # print('ENV Report after sample name filter')
            # print(envs.head())
                        
            # Minknow and Piranha version check
            if report['MinKNOWSoftwareVersion'].isnull().any():
                QMessageBox.warning(self, 'Warning', f'MinKNOW Software version information missing in report: {report_name}')
                return
            elif report['AnalysisPipelineVersion'].isnull().any():
                QMessageBox.warning(self, 'Warning', f'Analysis Pipeline version information missing in report: {report_name}')
                return
            
            # Verifies all EPIDs are present
            if report.EpidNumber.isnull().any():
                QMessageBox.warning(self, 'Warning', f'Missing EPIDs in {report_name}')
                text += 'This run has missing EPIDs, please complete report!\n'
                html += '<p><b><mark>This run has missing EPIDs, please complete report!</mark></b></p>\n'
                return

            # Filter for QC and Sample Passes, fill empty cells with empty string to not cause attribute error
            report['RunQC'] = report['RunQC'].fillna('').str.strip().str.title()
            report['SampleQC'] = report['SampleQC'].fillna('').str.strip().str.title()
            
            # Set to upper to find typos
            report['classification'] = report['classification'].str.upper().str.strip()
            
            if report.empty:
                text += f'Completely negative.\n'
                html += f'Completely negative</p>\n'
                print('Negative Report')
                continue
                
            # Standardising DDNS Classification for report
            def classify(row):
                classifications = []
                if row['Sabin1-related|classification'] == 'Sabin-like':
                    classifications.append('SABIN1')
                elif row['Sabin1-related|classification'] == 'VDPV':
                    classifications.append('VDPV1')

                if row['Sabin2-related|classification'] == 'Sabin-like':
                    classifications.append('SABIN2')
                elif row['Sabin2-related|classification'] == 'VDPV':
                    classifications.append('VDPV2')

                if row['Sabin3-related|classification'] == 'Sabin-like':
                    classifications.append('SABIN3')
                elif row['Sabin3-related|classification'] == 'VDPV':
                    classifications.append('VDPV3')

                return '+'.join(classifications) if classifications else 'Negative'

            # Apply the classify function to each row
            report['classification'] = report.apply(classify, axis=1)
            
            # Counts number of EPIDs that are negative
            neg_epid_count = report.loc[(report['classification'] == 'Negative')].drop_duplicates(subset='EpidNumber',keep='first').classification.value_counts()            
            
            # if all samples have a class then neg is 0
            if neg_epid_count.empty:
                neg_epid_count = pd.Series([0], index=['Negative'])
            
            # Summary counts for fails
            ddns_sample_fail = report.loc[report['SampleQC'] ==  'Fail']
            ddns_run_fail = report.loc[report['RunQC'] ==  'Fail']

            # Summary counts for passes
            ddns_pass = report.loc[report['SampleQC'] ==  'Pass']

            print('Checking QC values')
            print(report[['RunQC','SampleQC']].value_counts())
            
            # Adding to totals pass and fails
            ddns_total_pass = pd.concat([ddns_total_pass, ddns_pass], join='inner')
            ddns_total_sample_fail = pd.concat([ddns_total_sample_fail, ddns_sample_fail], join='inner')
            ddns_total_run_fail = pd.concat([ddns_total_run_fail, ddns_run_fail], join='inner')

            text += f'\nSummary count for run {report_name}\n'
            html += f'\n<h4>Summary count for run {report_name}</h4>'
            
            # Creating counts table
            table = pd.concat([ddns_pass.classification.value_counts(), ddns_sample_fail.classification.value_counts(), ddns_run_fail.classification.value_counts()], axis=1, ignore_index=False, keys=['Pass','Sample Fail','Run Fail']).fillna(0).astype(int).sort_index().reset_index(names=f'{report_mode} Classification')
            table.loc[len(table.index)] = ['Total', table['Pass'].sum(), table['Sample Fail'].sum(), table['Run Fail'].sum()] # Add total row

            text += (table.to_string(index=False, justify='left') + '\n\n')
            html += (table.to_html(index=False) + '\n')
            
            # Splitting on the + and create duplicate row below with explode
            if not report[report['classification'].str.contains('\\+', na=False)].empty:
                combos = report[report['classification'].str.contains('\\+', na=False)]
                combos.loc[:,'classification'] = combos['classification'].str.split("\\+")
                combos = combos.explode('classification')
                report = pd.concat([report,combos])

            # DDNS sample summariser
            for ddns_type in ['VDPV1', 'VDPV2', 'VDPV3']:
                # Selecting VDPV    
                ddns_report = report.loc[(report['classification'] == ddns_type)& (report['SampleQC'] == 'Pass')]         
                if not ddns_report.empty:
                    vdpv_found = True
                    #print('Found VDPV')
                    text += f'Samples with at least {10 if ddns_type == "VDPV1" or ddns_type == "VDPV3" else 6} VP1 nt differences compared to Sabin {ddns_type[-1]} that can be reported.\n'
                    html += f'<p>Samples with at least {10 if ddns_type == "VDPV1" or ddns_type == "VDPV3" else 6} VP1 nt differences compared to Sabin {ddns_type[-1]} that can be reported.</p>\n<ul>'
                    
                    for EPID in set(ddns_report['EpidNumber'].dropna().values):
                        # Grab EPID row and nt diff info
                        epid_row = ddns_report[ddns_report['EpidNumber'] == EPID]                        
                        nt_diff = int(epid_row[f'Sabin{ddns_type[-1]}-related|nt_diff_from_reference'].dropna().values[0])
                        
                        # Lineage extraction
                        # epid_row['lineage'] = epid_row['EmergenceGroupVDPV1'].combine_first(epid_row['EmergenceGroupVDPV2']).combine_first(epid_row['EmergenceGroupVDPV3'])
                        # epid_row['lineage'] = epid_row['lineage'].fillna('').astype('str').str.strip()
                        
                        # Grab emergence group info
                        # if epid_row['lineage'].ne('').all():
                        #     lineage = epid_row['lineage'].unique()[0].upper()
                        # else:
                            # lineage = 'LINEAGE_HERE' # Placeholder if empty

                        # since the latest DDNS headers have removed the emergence group columns, lineage will be set to UNKNOWN
                        lineage = 'UNKNOWN'
                        
                        # Handles pairs
                        if len(epid_row[ddns_report.columns[0]].values) == 2:
                            text += f'•\t{epid_row["EpidNumber"].values[0]} ({epid_row[ddns_report.columns[0]].values[0]}, {epid_row[ddns_report.columns[0]].values[1]}): {nt_diff} nucleotide differences.\n'
                            html += f'<li>{epid_row["EpidNumber"].values[0]} ({epid_row[ddns_report.columns[0]].values[0]}, {epid_row[ddns_report.columns[0]].values[1]}): {nt_diff} nucleotide differences.\n'
                        # Handles loner sample
                        else:
                            text += f'•\t{epid_row["EpidNumber"].values[0]} ({epid_row[ddns_report.columns[0]].values[0]}): {nt_diff} nucleotide differences.\n'
                            html += f'<li>\t{epid_row["EpidNumber"].values[0]} ({epid_row[ddns_report.columns[0]].values[0]}): {nt_diff} nucleotide differences.\n'

                        # GPEI statement
                        text += f'Genetically related to {lineage}. This sample is immediately classified as {ddns_type} as described in GPEI Guidelines for reporting and Classification of Vaccine-derived Polioviruses.\n\n'
                        html += f'Genetically related to <b><mark>{lineage}</mark></b>. This sample is immediately classified as <b><mark>{ddns_type}</mark></b> as described in GPEI Guidelines for reporting and Classification of Vaccine-derived Polioviruses.\n\n'
                
                # Stops trailing end list characters from loops, for nicer looking html
                if html[-5:] == "</ul>":
                    html += ''
                else:
                    html += '</ul>'
                    
            if html[-5:] == "</ul>":
                html += ''
            else:
                html += '</ul>'
            
            # Prints text if No VDPVs present
            if not vdpv_found:
                text += f"\nNo VDPVs to report were found\n"     
                html += f"<p>No VDPVs to report were found</p>\n"    
            
            # Displaying Sabin positive values
            if  report_mode == 'DDNS':
                for ddns_type in ['SABIN1', 'SABIN2', 'SABIN3']:
                    # Selecting Sabin
                    ddns_report = report.loc[(report['classification'] == ddns_type) & (report['SampleQC'] == 'Pass')]
                    if not ddns_report.empty:
                        sabin_found = True
                        text += f'\nSamples with less than {10 if ddns_type == "SABIN1" or ddns_type == "SABIN3" else 6} VP1 nt differences compared to Sabin{ddns_type[-1]} that can be reported:\n'
                        html += f'<p>Samples with less than {10 if ddns_type == "SABIN1" or ddns_type == "SABIN3" else 6} VP1 nt differences compared to Sabin{ddns_type[-1]} that can be reported:<p/>\n<ul>'

                        for EPID in set(ddns_report['EpidNumber'].dropna().values):
                            # Grab EPID row and nt diff info
                            epid_row = ddns_report[ddns_report['EpidNumber'] == EPID]
                            nt_diff = int(epid_row[f'Sabin{ddns_type[-1]}-related|nt_diff_from_reference'].dropna().values[0])
                            
                            # Handles pairs
                            if len(epid_row[ddns_report.columns[0]].values) == 2:
                                text += f'•\t{epid_row["EpidNumber"].values[0]} ({epid_row[ddns_report.columns[0]].values[0]}, {epid_row[ddns_report.columns[0]].values[1]}): {nt_diff} nucleotide differences.\n'
                                html += f'<li>{epid_row["EpidNumber"].values[0]} ({epid_row[ddns_report.columns[0]].values[0]}, {epid_row[ddns_report.columns[0]].values[1]}): {nt_diff} nucleotide differences.\n'
                            
                            # Handles loner sample
                            else:
                                text += f'•\t{epid_row["EpidNumber"].values[0]} ({epid_row[ddns_report.columns[0]].values[0]}): {nt_diff} nucleotide differences.\n'
                                html += f'<li>{epid_row["EpidNumber"].values[0]} ({epid_row[ddns_report.columns[0]].values[0]}): {nt_diff} nucleotide differences.\n'
                    # Stops trailing end list characters from loops, for nicer looking html
                    if html[-5:] == "</ul>":
                        html += ''
                    else:
                        html += '</ul>'
                        
                if html[-5:] == "</ul>":
                    html += ''
                else:
                    html += '</ul>'
            
                # No Sabin statement
                if not sabin_found:
                    text += f"No Sabins to report were found\n" 
                    html += f"<p>No Sabins to report were found</p>\n"
            
            print(envs[['sample','classification','SampleQC']])
            
            # ENV sample summariser
            for ddns_type in ['VDPV1', 'VDPV2', 'VDPV3']:
                # Selecting VDPV    
                env_report = envs.loc[(envs['classification'] == ddns_type) & (envs['SampleQC'] == 'Pass')]       
                if not env_report.empty:
                    vdpv_found = True
                    #print('Found VDPV')
                    text += f'\nEnvironmental Samples with at least {10 if ddns_type == "VDPV1" or ddns_type == "VDPV3" else 6} VP1 nt differences compared to Sabin {ddns_type[-1]} that can be reported.\n'
                    html += f'<p>Environmental Samples Samples with at least {10 if ddns_type == "VDPV1" or ddns_type == "VDPV3" else 6} VP1 nt differences compared to Sabin {ddns_type[-1]} that can be reported.</p>\n<ul>'
                    
                    for s in set(env_report['sample'].dropna().values):
                        # Grab EPID row and nt diff info
                        s_row = env_report[env_report['sample'] == s]
                        print(s_row)                     
                        nt_diff = int(s_row[f'Sabin{ddns_type[-1]}-related|nt_diff_from_reference'].dropna().values[0])
                        
                        # Lineage extraction
                        # s_row['lineage'] = s_row['EmergenceGroupVDPV1'].combine_first(s_row['EmergenceGroupVDPV2']).combine_first(s_row['EmergenceGroupVDPV3'])
                        # s_row['lineage'] = s_row['lineage'].fillna('').astype('str').str.strip()
                        
                        # # Grab emergence group info
                        # if s_row['lineage'].ne('').all():
                        #     lineage = s_row['lineage'].unique()[0].upper()
                        # else:
                        #     lineage = 'LINEAGE_HERE' # Placeholder if empty
                        lineage = 'UNKNOWN'
                        
                        text += f'•\t{s_row[env_report.columns[0]].values[0]}: {nt_diff} nucleotide differences.\n'
                        html += f'<li>\t{s_row[env_report.columns[0]].values[0]}: {nt_diff} nucleotide differences.\n'

                        # GPEI statement
                        text += f'Genetically related to {lineage}. This sample is immediately classified as {ddns_type} as described in GPEI Guidelines for reporting and Classification of Vaccine-derived Polioviruses.\n\n'
                        html += f'Genetically related to <b><mark>{lineage}</mark></b>. This sample is immediately classified as <b><mark>{ddns_type}</mark></b> as described in GPEI Guidelines for reporting and Classification of Vaccine-derived Polioviruses.\n\n'
                
                # Stops trailing end list characters from loops, for nicer looking html
                if html[-5:] == "</ul>":
                    html += ''
                else:
                    html += '</ul>'
                
            if html[-5:] == "</ul>":
                html += ''
            else:
                html += '</ul>'
                
                
            # Minknow and Piranha statement
            try:
                minknow_ver = report['MinKNOWSoftwareVersion'].unique()[0]
            except:
                print('Tried to get minknow versions')
                print(report_name)
                print(report)
                
            try:
                piranha_ver = report['AnalysisPipelineVersion'].unique()[0]
            except:
                print('Tried to get piranha versions')
                print(report_name)
                print(report)
                
            html += f"Minknow version {minknow_ver} and Piranha version {piranha_ver} was used to generate the data reported here\n"
                
            # Stating number of negative EPIDs
            text += f'\nNumber of Negative EPIDs: {neg_epid_count.values[0]}\n'
            html += f'\n<p>Number of Negative EPIDs: {neg_epid_count.values[0]}</p>' 

        # Totals, applied in reverse order since adding to the top of text
        total_table = pd.concat([ddns_total_pass.classification.value_counts(), ddns_total_sample_fail.classification.value_counts(), ddns_total_run_fail.classification.value_counts()], axis=1, ignore_index=False, keys=['Pass','Sample Fail','Run Fail']).fillna(0).astype(int).sort_index().reset_index(names=f'{report_mode} Classification')
        print(total_table)
        # table with negs
        total_table_no_neg = total_table[total_table[f'{report_mode} Classification'] != 'Negative']
        
        # total row appended
        total_table.loc[len(total_table.index)] = ['Total', total_table['Pass'].sum(), total_table['Sample Fail'].sum(), total_table['Run Fail'].sum()] # Add total row
        
        # total - neg row appended
        total_table.loc[len(total_table.index)] = ['Total (Negatives excluded)', total_table_no_neg['Pass'].sum(), total_table_no_neg['Sample Fail'].sum(), total_table_no_neg['Run Fail'].sum()]

        
        text = (total_table.to_string(index=False, justify='left') + '\n') + text
        text = 'Summary count table for all runs\n' + text
        
        html = (total_table.to_html(index=False) + '\n') + html
        html = '<h2>Summary count table for all Runs</h2>' + html
        
        # Run list at beginning of report
        text = "\n" + text
        html = "</ul>\n" + html
        
        for path in reversed(paths):
            report_name = path.rsplit('/')[-1].rsplit('_',3)[0]
            text = f"\t• {report_name}\n" + text
            html = f"<li>{report_name}\n" + html
                        
        text = "Runs present in this report:\n" + text
        html = "Runs present in this report:\n<ul>" + html
        
        #Title
        if len(report_name_list) > 1:
            text = f"DDNS Report for Runs {report_name_list[0]} to {report_name_list[-1]}\n\n" + text
            html = f"<h1>DDNS REPORT FOR RUNS {report_name_list[0]} TO {report_name_list[-1]}</h1>" + html
            html_file_output = f"{destination_path}/{report_mode}_report_{report_name_list[0]}_to_{report_name_list[-1]}.html"
        else:
            text = f"DDNS Report For Run {report_name_list[0]}\n\n" + text
            html = f"<h1>DDNS REPORT FOR RUN {report_name_list[0]}</h1>" + html
            html_file_output = f"{destination_path}/{report_mode}_report_{report_name_list[0]}.html"
        
        # Acknowledgments
        html += "<p>These data were produced using polio sequencing <a href='https://www.protocols.io/workspaces/poliovirus-sequencing-consortium/about'>Protocols</a> and analysis <a href='https://github.com/polio-nanopore/piranha'>software</a> developed by the <a href='https://polionanopore.org/about.html'>Polio Sequencing Consortium</a></p>"        
        # Setting Style header for Report      
        html = "<html>\n<head>\n<style>\n\n\ttable {margin: 40px;}\n\tth {background-color: #00008B;color: white;}\n\ttable, th, td {border-collapse: collapse; padding: 5px;}\n\tmark {background-color: white;color: red;}\n\n</style>\n</head>\n<body>" + html + "\n</body>\n</html>"
        
        # Text Output
        self.textbox.setPlainText(text)
        
        # HTML Output
        try:
            with open(html_file_output,"w") as output:
                print(html, file=output)
                
        except PermissionError:
            QMessageBox.warning(self, 'Warning', 'No permission for destination')
            return

    def clear_list(self):
        self.listbox_view.clear()
        self.textbox.clear()
        #self.destination_entry.clear()
        bg_label.setText('Drop CSV or XLSX files here')
        bg_label.show()


if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        prog = App()
        prog.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.error("Application initialization failed", exc_info=True)
        print(f"Application failed to start: {str(e)}")
