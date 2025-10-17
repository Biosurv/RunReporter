# IMPORTS
import sys, os, logging
from logging.handlers import RotatingFileHandler
import pandas as pd
from collections import defaultdict
from updater import UpdateChecker
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QSettings
from PyQt5.QtGui import QPixmap, QFont, QIcon, QClipboard
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QListWidget, QLineEdit, QPushButton, QMessageBox, QLabel,
    QFileDialog, QPlainTextEdit, QComboBox, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QSizePolicy,
    QStackedLayout
)
import json
import html as html_std

# AUTHORS - Shean Mobed, Matthew Anderson
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
V1.5.7 --> V1.5.8
- Added run number info to control pop-up and ability to cancel report generation if controls are invalid
- Added version checking against latest release on GitHub

V1.5.8 --> V1.5.9
- Improved report styling
- Removed failed runs from run specific summaries
- Fixed issue where sample fails were still counted despite a run failing
- Added support for wild type polioviruses
- Added country and lab inputs for report

"""
version = '1.5.9'

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

        if type.lower() == "warning":
            self.setIcon(QMessageBox.Warning)
        elif type.lower() in ("info", "information"):
            self.setIcon(QMessageBox.Information)
            self.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        elif type.lower() == "error":
            self.setIcon(QMessageBox.Critical)
        else:
            self.setIcon(QMessageBox.NoIcon)

        warning_style = """
            QMessageBox {background-color: white;color: black;}
            QMessageBox QLabel {color: black;}
            QMessageBox QPushButton {background-color: #ff9800; color: black;padding: 5px;border-radius: 3px; min-width: 80px; margin-left: auto; margin-right: auto;}
            QMessageBox QPushButton:hover {background-color: #e68900;}
        """
        information_style = """
            QMessageBox {background-color: white; color: black;}
            QMessageBox QLabel {color: black;}
            QMessageBox QPushButton {background-color: #ff9800; color: black;padding: 5px;border-radius: 3px; min-width: 80px; margin-left: auto; margin-right: auto;}
            QMessageBox QPushButton:hover {background-color: #e68900;}
        """
        self.setStyleSheet(warning_style if type.lower() == "warning" else information_style)

    def ask_confirmation(self):
        result = self.exec_()
        return result != QMessageBox.Cancel

# APP
class ListBoxWidget(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.resize(500, 500)
        self.bg_label = None

    def dragEnterEvent(self, event):
        if hasattr(self, 'bg_label'):
            self.bg_label.hide()
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
        allowed_extensions = ('.csv', '.xlsx')
        urls = event.mimeData().urls()
        file_paths = [url.toLocalFile() for url in urls if url.toLocalFile().lower().endswith(allowed_extensions)]
        self.addItems(file_paths)
        if hasattr(self, 'bg_label'):
            self.bg_label.hide()

    def resizeEvent(self, event):
        if self.bg_label is not None:
            self.bg_label.resize(self.size())
        super().resizeEvent(event)


class App(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Run Reporter")
        self.setWindowIcon(QIcon(os.path.join(os.path.dirname(__file__), "assets/Icon.ico")))
        QSettings("Biosurv International", "RunReporter").clear()

        self.updater = UpdateChecker(
            owner="Biosurv",
            repo="RunReporter",
            current_version=version,
            check_prereleases=False,
            min_interval_minutes=0,
            github_token=None,
            settings_org="Biosurv International",
            settings_app="RunReporter",
        )

        
        self.updater.check_on_startup(parent=self, force=True)

        # Central widget and main layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(10)

        # Top
        top_layout = QHBoxLayout()
        self.logo_label = QLabel()
        self.logo_label.setPixmap(QPixmap(os.path.join(os.path.dirname(__file__), 'assets/Logo.png')))
        self.logo_label.setScaledContents(True)
        self.logo_label.setFixedSize(80, 80)
        top_layout.addWidget(self.logo_label, 0, Qt.AlignLeft)

        title_layout = QVBoxLayout()
        self.title = QLabel('Run Reporter')
        self.title.setFont(QFont('Arial', 18))
        self.title.setStyleSheet("background-color:transparent")
        title_layout.addWidget(self.title, 0, Qt.AlignCenter)

        self.version_label = QLabel(f'Version: {version}')
        self.version_label.setFont(QFont('Arial', 9))
        self.version_label.setStyleSheet("background-color:transparent")
        title_layout.addWidget(self.version_label, 0, Qt.AlignCenter)
        top_layout.addLayout(title_layout, 1)

        main_layout.addLayout(top_layout)

        # Mode selection
        mode_layout = QHBoxLayout()
        self.mode_label = QLabel('Mode:')
        self.mode_label.setFont(QFont('Arial', 9))
        self.mode_label.setStyleSheet("background-color:transparent")
        mode_layout.addWidget(self.mode_label)
        self.mode = QComboBox()
        self.mode.addItems(["DDNS", "Isolate"])
        self.mode.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        mode_layout.addWidget(self.mode)
        main_layout.addLayout(mode_layout)

        # Dropbox with overlay label
        dropbox_layout = QVBoxLayout()
        self.listbox_label = QLabel('Dropbox:')
        self.listbox_label.setFont(QFont('Arial', 9))
        self.listbox_label.setStyleSheet("background-color:transparent")
        dropbox_layout.addWidget(self.listbox_label)

        # Stacked layout for dropbox and overlay label
        dropbox_stack = QStackedLayout()
        self.listbox_view = ListBoxWidget(self)
        self.listbox_view.setStyleSheet("background-color:#FAF9F6;border-color:lightgrey;border-style:dashed;border-width:2px;border-radius:10px;")
        self.listbox_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Country + Lab inputs
        meta_layout = QHBoxLayout()

        self.country_label = QLabel('Country:')
        self.country_label.setFont(QFont('Arial', 9))
        self.country_label.setStyleSheet("background-color:transparent")
        meta_layout.addWidget(self.country_label)

        self.country_entry = QLineEdit()
        self.country_entry.setFont(QFont('Arial', 11))
        self.country_entry.setStyleSheet("background-color:#FAF9F6;border-color:lightgrey;border-style:dashed;border-width:2px;border-radius:10px;")
        meta_layout.addWidget(self.country_entry, 1)

        self.lab_label = QLabel('Lab:')
        self.lab_label.setFont(QFont('Arial', 9))
        self.lab_label.setStyleSheet("background-color:transparent")
        meta_layout.addWidget(self.lab_label)

        self.lab_entry = QLineEdit()
        self.lab_entry.setFont(QFont('Arial', 11))
        self.lab_entry.setStyleSheet("background-color:#FAF9F6;border-color:lightgrey;border-style:dashed;border-width:2px;border-radius:10px;")
        meta_layout.addWidget(self.lab_entry, 1)

        main_layout.addLayout(meta_layout)

        # Overlay label
        self.bg_label = QLabel('Drop CSV or XLSX files here', self.listbox_view)
        self.bg_label.setAlignment(Qt.AlignCenter)
        self.bg_label.setStyleSheet("background:transparent; color: #888; font-size: 18px;")
        self.bg_label.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.bg_label.setGeometry(0, 0, 1, 1)
        self.listbox_view.bg_label = self.bg_label 

        dropbox_stack.addWidget(self.listbox_view)
        dropbox_stack.setStackingMode(QStackedLayout.StackAll)
        dropbox_layout.addLayout(dropbox_stack)
        dropbox_layout.setStretch(1, 1)
        main_layout.addLayout(dropbox_layout)

        # Destination
        dest_layout = QHBoxLayout()
        self.destination_label = QLabel('Destination:')
        self.destination_label.setFont(QFont('Arial', 9))
        self.destination_label.setStyleSheet("background-color:transparent")
        dest_layout.addWidget(self.destination_label)
        self.destination_entry = QLineEdit()
        self.destination_entry.setFont(QFont('Arial', 11))
        self.destination_entry.setStyleSheet("background-color:#FAF9F6;border-color:lightgrey;border-style:dashed;border-width:2px;border-radius:10px;")
        dest_layout.addWidget(self.destination_entry, 1)
        self.destination_btn = QPushButton('Destination')
        self.destination_btn.setFont(QFont('Arial', 9))
        self.destination_btn.setStyleSheet("QPushButton{color: black; border-radius: 15px;background-color:#f7ae6c;border-color:black;border-style: solid;border-width: 1px;}QPushButton::pressed{background-color : #fce0b0;}")
        self.destination_btn.clicked.connect(lambda: self.select_destination(3))
        dest_layout.addWidget(self.destination_btn)
        main_layout.addLayout(dest_layout)

        # Report textbox
        self.textbox_label = QLabel('Report:')
        self.textbox_label.setFont(QFont('Arial', 9))
        self.textbox_label.setStyleSheet("background-color:transparent")
        main_layout.addWidget(self.textbox_label)
        self.textbox = QPlainTextEdit()
        self.textbox.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(self.textbox, 2)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_save = QPushButton('Generate Report')
        self.btn_save.setFont(QFont('Arial', 9))
        self.btn_save.setStyleSheet("QPushButton{color: black; border-radius: 15px;background-color:#f7ae6c;border-color:black;border-style: solid;border-width: 1px;}QPushButton::pressed{background-color : #fce0b0;}")
        self.btn_save.clicked.connect(self.parse_csv)
        btn_layout.addWidget(self.btn_save)

        self.btn_clear = QPushButton('Clear')
        self.btn_clear.setFont(QFont('Arial', 9))
        self.btn_clear.setStyleSheet("QPushButton{color: black; border-radius: 15px;background-color:#f7ae6c;border-color:black;border-style: solid;border-width: 1px;}QPushButton::pressed{background-color : #fce0b0;}")
        self.btn_clear.clicked.connect(self.clear_list)
        btn_layout.addWidget(self.btn_clear)

        self.btn_copy = QPushButton('Copy')
        self.btn_copy.setFont(QFont('Arial', 9))
        self.btn_copy.setStyleSheet("QPushButton{color: black; border-radius: 15px;background-color:#f7ae6c;border-color:black;border-style: solid;border-width: 1px;}QPushButton::pressed{background-color : #fce0b0;}")
        self.btn_copy.clicked.connect(self.copy_text_to_clipboard)
        btn_layout.addWidget(self.btn_copy)

        main_layout.addLayout(btn_layout)

        # Make widgets expand with window
        for widget in [self.textbox, self.listbox_view]:
            widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Optionally: set minimum size for usability
        self.setMinimumSize(800, 600)

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
            essential_cols = ['sample','DDNSclassification','EPID','RunQC','SampleQC',
                            'AnalysisPipelineVersion','MinKNOWSoftwareVersion',
                            'Sabin1-related|classification','Sabin1-related|nt_diff_from_reference',
                            'Sabin2-related|classification','Sabin2-related|nt_diff_from_reference',
                            'Sabin3-related|classification','Sabin3-related|nt_diff_from_reference']
        else:
            essential_cols = ['sample','IsolateClassification','EPID','RunQC','SampleQC',
                'AnalysisPipelineVersion','MinKNOWSoftwareVersion',
                'Sabin1-related|classification','Sabin1-related|nt_diff_from_reference',
                'Sabin2-related|classification','Sabin2-related|nt_diff_from_reference',
                'Sabin3-related|classification','Sabin3-related|nt_diff_from_reference']
        
        # WPV columns
        wpv_cols = ['WPV1|classification', 'WPV2|classification', 'WPV3|classification']

        col_rename_dict = {
        'DDNSclassification':'classification',
        'IsolateClassification':'classification'}

        invalid_samples = []
        invalid_map = defaultdict(set)
        num_reports = len(paths)
        counter = 0

        # Collect per-run HTML panels
        html_runs = []
        report_name_list = []

        # Track passed/failed runs for header pills and counting
        passed_report_names = []
        failed_runs = []

        run_fail_sample_total = 0  

        for path in paths:
            counter += 1
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
            
            
            if report.empty:
                print(f'Report: {report_name} has been read in as an empty dataframe')
                continue
            
            # Start per-run HTML
            run_html = f'''
            <div class="panel-inner">
                <h3>Run: <span class="run-name">{html_std.escape(report_name)}</span></h3>
            '''
    
            
            vdpv_found = False
            sabin_found = False
            wpv_found = False 

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

            # RunQC detection
            run_failed = False
            run_fail_reason = None

            if fail_CP_negative.any():
                run_failed = True
                run_fail_reason = 'Negative Positive Control'
                report['RunQC'] = 'Fail'
                text += 'This run has failed its RunQC, due to a Negative Positive Control\n'
                run_html += '<p><b><mark>This run has failed its RunQC, due to a Negative Positive Control</mark></b></p>\n'

            elif fail_CP_contaminated.any():
                run_failed = True
                run_fail_reason = 'Contaminated Positive Control'
                report['RunQC'] = 'Fail'
                text += 'This run has failed its RunQC, due to a Contaminated Positive Control\n'
                run_html += '<p><b><mark>This run has failed its RunQC, due to a Contaminated Positive Control</mark></b></p>\n'

            elif fail_CN_contaminated.any():
                run_failed = True
                run_fail_reason = 'Contaminated Negative Control'
                report['RunQC'] = 'Fail'
                text += 'This run has failed its RunQC, due to a Contaminated Negative Control\n'
                run_html += '<p><b><mark>This run has failed its RunQC, due to a Contaminated Negative Control</mark></b></p>\n'

            elif 'Fail' in report['RunQC'].fillna('').str.title().values:
                run_failed = True
                run_fail_reason = 'Run flagged as Fail in report metadata'

            # If the run failed record reason
            if run_failed:
                failed_runs.append((report_name, run_fail_reason))

                # Include true samples
                standard_mask = report['sample'].astype(str).str.match(r'^[A-Z]{3}[/-]\d{2}[/-]\d{3,5}')
                env_mask = report['sample'].astype(str).str.match(r'^ENV-[A-Z]{3}[/-]\d{2}[/-]\d{3,5}')
                valid_sample_mask = standard_mask | env_mask

                n_samples = report.loc[valid_sample_mask, 'sample'].dropna().astype(str).nunique()

                run_fail_sample_total += int(n_samples)
                continue

            passed_report_names.append(report_name)
            
            envs = report.loc[report['sample'].str.match(r'^ENV-[A-Z]{3}[/-]\d{2}[/-]\d{3,5}')]

            mask = report['sample'].str.match(r'^[A-Z]{3}[/-]\d{2}[/-]\d{3,5}')

            invalid_in_report = (
                report.loc[~mask, 'sample']
                .dropna()
                .astype(str)
                .tolist()
            )

            invalid_samples.extend(invalid_in_report)

            for s in invalid_in_report:
                invalid_map[s].add(report_name)

            # Keep only valid samples
            report = report.loc[mask]

            if counter == num_reports:
                if invalid_map: 
                    lines = []
                    for sample, runs in sorted(invalid_map.items()):
                        lines.append(f"<b>{sample}</b> - {', '.join(sorted(runs))}")

                    msg_text = (
                        "The following sample IDs have been identified as controls "
                        "and will be removed:<br><br>"
                        + "<br>".join(lines)
                    )

                    msg = CustomMessageBox("info", msg_text)
                    if not msg.ask_confirmation():
                        self.clear_list()
                        return
                        
            # Minknow and Piranha version check
            if report['MinKNOWSoftwareVersion'].isnull().any():
                QMessageBox.warning(self, 'Warning', f'MinKNOW Software version information missing in report: {report_name}')
                return
            elif report['AnalysisPipelineVersion'].isnull().any():
                QMessageBox.warning(self, 'Warning', f'Analysis Pipeline version information missing in report: {report_name}')
                return
            
            # Verifies all EPIDs are present
            if report.EPID.isnull().any():
                QMessageBox.warning(self, 'Warning', f'Missing EPIDs in {report_name}')
                text += 'This run has missing EPIDs, please complete report!\n'
                run_html += '<p><b><mark>This run has missing EPIDs, please complete report!</mark></b></p>\n'
                run_html += '</div>'
                html_runs.append(run_html)
                continue

            # Filter for QC and Sample Passes
            report['RunQC'] = report['RunQC'].fillna('').str.strip().str.title()
            report['SampleQC'] = report['SampleQC'].fillna('').str.strip().str.title()
            
            
            report['classification'] = report['classification'].str.upper().str.strip()
            
            if report.empty:
                text += f'Completely negative.\n'
                run_html += f'<p>Completely negative</p>\n'
                print('Negative Report')
                run_html += '</div>'
                html_runs.append(run_html)
                continue
                
            # Standardising DDNS Classification for report
            def classify(row):
                
                def val(col):
                    return str(row.get(col, '')).strip().upper()

                classifications = []
                
                if val('Sabin1-related|classification') == 'SABIN-LIKE':
                    classifications.append('SABIN1')
                elif val('Sabin1-related|classification') == 'VDPV':
                    classifications.append('VDPV1')

                if val('Sabin2-related|classification') == 'SABIN-LIKE':
                    classifications.append('SABIN2')
                elif val('Sabin2-related|classification') == 'VDPV':
                    classifications.append('VDPV2')

                if val('Sabin3-related|classification') == 'SABIN-LIKE':
                    classifications.append('SABIN3')
                elif val('Sabin3-related|classification') == 'VDPV':
                    classifications.append('VDPV3')

                
                if val('WPV1|classification') == 'WPV1':
                    classifications.append('WPV1')
                if val('WPV2|classification') == 'WPV2':
                    classifications.append('WPV2')
                if val('WPV3|classification') == 'WPV3':
                    classifications.append('WPV3')

                return '+'.join(classifications) if classifications else 'Negative'

        
            report['classification'] = report.apply(classify, axis=1)
            
            # Counts number of EPIDs that are negative
            neg_epid_count = report.loc[(report['classification'] == 'Negative')].drop_duplicates(subset='EPID',keep='first').classification.value_counts()            
            
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
            
            # Adding to totals for non-failed runs
            ddns_total_pass = pd.concat([ddns_total_pass, ddns_pass], join='inner')
            ddns_total_sample_fail = pd.concat([ddns_total_sample_fail, ddns_sample_fail], join='inner')
            

            table = pd.concat(
                [
                    ddns_pass.classification.value_counts(),
                    ddns_sample_fail.classification.value_counts()
                ],
                axis=1, keys=['Pass', 'Sample Fail']
            ).fillna(0).astype(int).sort_index().reset_index(names=f'{report_mode} Classification')

            table.loc[len(table.index)] = [
                'Total',
                int(table['Pass'].sum()),
                int(table['Sample Fail'].sum())
            ]

            text += (table.to_string(index=False, justify='left') + '\n\n')
            run_html += (table.to_html(index=False, classes="compact striped") + '\n')
            
            if not report[report['classification'].str.contains('\\+', na=False)].empty:
                combos = report[report['classification'].str.contains('\\+', na=False)]
                combos.loc[:,'classification'] = combos['classification'].str.split("\\+")
                combos = combos.explode('classification')
                report = pd.concat([report,combos])

            # DDNS sample summariser (VDPV)
            vdpv_sections_html = []
            for ddns_type in ['VDPV1', 'VDPV2', 'VDPV3']:
                ddns_report = report.loc[
                    (report['classification'] == ddns_type) &
                    (report['SampleQC'] == 'Pass')
                ]
                if ddns_report.empty:
                    continue

                vdpv_found = True
                diff_limit = 10 if ddns_type in ('VDPV1', 'VDPV3') else 6

                section_html = (
                    f'<p><b>Samples with at least {diff_limit} VP1 nt differences compared to '
                    f'Sabin {ddns_type[-1]} that can be reported:</b></p>\n<ul>'
                )
                text += (
                    f'Samples with at least {diff_limit} VP1 nt differences compared to '
                    f'Sabin {ddns_type[-1]} that can be reported.\n'
                )

                for EPID in sorted(set(ddns_report['EPID'].dropna().values)):
                    epid_row = ddns_report[ddns_report['EPID'] == EPID]
                    nt_diff = int(
                        epid_row[f'Sabin{ddns_type[-1]}-related|nt_diff_from_reference']
                        .dropna().values[0]
                    )
                    lineage = 'UNKNOWN'

                    names = list(epid_row[ddns_report.columns[0]].values)
                    if len(names) == 2:
                        bullet = f'{EPID} ({names[0]}, {names[1]}): {nt_diff} nucleotide differences.'
                    else:
                        bullet = f'{EPID} ({names[0]}): {nt_diff} nucleotide differences.'

                    section_html += (
                        f'<li>{bullet} '
                        f'<span class="muted">Genetically related to <span class="hi-red">{lineage}</span>. '
                        f'Immediately classified as <span class="hi-red">{ddns_type}</span> as described in GPEI Guidelines for reporting and classification of Vaccine-derived Polioviruses.</span></li>\n'
                    )

                    text += f'•\t{bullet}\n'
                    text += (
                        f'Genetically related to {lineage}. This sample is immediately classified as '
                        f'{ddns_type} as described in GPEI Guidelines for reporting and classification of '
                        f'Vaccine-derived Polioviruses.\n\n'
                    )

                section_html += '</ul>'
                vdpv_sections_html.append(section_html)

            if vdpv_sections_html:
                run_html += '\n'.join(vdpv_sections_html)
            
            if not vdpv_found:
                text += f"\nNo VDPVs to report were found\n"     
                run_html += f"<p>No VDPVs to report were found</p>\n"    
            
            # Sabin positives
            if report_mode == 'DDNS':
                sabin_html_sections = []
                for ddns_type in ['SABIN1', 'SABIN2', 'SABIN3']:
                    ddns_report = report.loc[
                        (report['classification'] == ddns_type) &
                        (report['SampleQC'] == 'Pass')
                    ]
                    if not ddns_report.empty:
                        sabin_found = True
                        diff_limit = 10 if ddns_type in ['SABIN1', 'SABIN3'] else 6
                        section = f'<p><b>Samples with less than {diff_limit} VP1 nt differences compared to {ddns_type.title()} that can be reported:</b></p>\n<ul>'
                        text += f'\nSamples with less than {diff_limit} VP1 nt differences compared to {ddns_type.title()} that can be reported:\n'

                        for EPID in sorted(set(ddns_report['EPID'].dropna().values)):
                            epid_row = ddns_report[ddns_report['EPID'] == EPID]
                            nt_diff = int(epid_row[f'Sabin{ddns_type[-1]}-related|nt_diff_from_reference'].dropna().values[0])

                            names = list(epid_row[ddns_report.columns[0]].values)
                            if len(names) == 2:
                                bullet = f'{EPID} ({names[0]}, {names[1]}): {nt_diff} nucleotide differences.'
                            else:
                                bullet = f'{EPID} ({names[0]}): {nt_diff} nucleotide differences.'

                            section += f'<li>{bullet}</li>\n'
                            text += f'•\t{bullet}\n'
                        section += '</ul>'
                        sabin_html_sections.append(section)

                if sabin_html_sections:
                    run_html += '\n'.join(sabin_html_sections)
                else:
                    text += "No Sabins to report were found\n"
                    run_html += "<p>No Sabins to report were found</p>\n"

            # Wild Poliovirus (WPV1/2/3)
            wpv_sections_html = []
            for wpv_type in ['WPV1', 'WPV2', 'WPV3']:
                wpv_report = report.loc[
                    (report['classification'] == wpv_type) &
                    (report['SampleQC'] == 'Pass')
                ]
                if wpv_report.empty:
                    continue

                wpv_found = True

                
                section_html = (
                    f'<p><b>Samples detected as {wpv_type} (wild poliovirus) that can be reported:</b></p>\n<ul>'
                )
                text += f'Samples detected as {wpv_type} (wild poliovirus) that can be reported.\n'

                for EPID in sorted(set(wpv_report['EPID'].dropna().values)):
                    epid_row = wpv_report[wpv_report['EPID'] == EPID]
                    names = list(epid_row[wpv_report.columns[0]].values)
                    if len(names) == 2:
                        sample_str = f'{EPID} ({names[0]}, {names[1]})'
                    else:
                        sample_str = f'{EPID} ({names[0]})'

                    section_html += (
                        f'<li>{sample_str}. '
                    )
                    text += f'•\t{sample_str}\n'

                section_html += '</ul>'
                wpv_sections_html.append(section_html)

            if wpv_sections_html:
                run_html += '\n'.join(wpv_sections_html)

            # ENV sample summariser (VDPV)
            env_sections_html = []
            for ddns_type in ['VDPV1', 'VDPV2', 'VDPV3']:
                env_report = envs.loc[(envs['classification'] == ddns_type) & (envs['SampleQC'] == 'Pass')]
                if env_report.empty:
                    continue

                vdpv_found = True
                diff_limit = 10 if ddns_type in ('VDPV1', 'VDPV3') else 6

                section_html = (
                    f'<p><b>Environmental samples with at least {diff_limit} VP1 nt differences '
                    f'compared to Sabin {ddns_type[-1]} that can be reported:</b></p>\n<ul>'
                )
                text += (
                    f'\nEnvironmental samples with at least {diff_limit} VP1 nt differences compared '
                    f'to Sabin {ddns_type[-1]} that can be reported:\n'
                )

                for s in sorted(set(env_report['sample'].dropna().values)):
                    s_row = env_report[env_report['sample'] == s]
                    nt_diff = int(s_row[f'Sabin{ddns_type[-1]}-related|nt_diff_from_reference'].dropna().values[0])
                    lineage = 'UNKNOWN'

                    section_html += (
                        f'<li>{s}: {nt_diff} nucleotide differences. '
                        f'<span class="muted">Genetically related to <span class="hi-red">{lineage}</span>. '
                        f'Immediately classified as <span class="hi-red">{ddns_type}</span> as described in GPEI Guidelines for reporting and classification of Vaccine-derived Polioviruses.</span></li>\n'
                    )

                    text += f'•\t{s}: {nt_diff} nucleotide differences.\n'
                    text += (
                        f'Genetically related to {lineage}. This sample is immediately classified as '
                        f'{ddns_type} as described in GPEI Guidelines for reporting and Classification of '
                        f'Vaccine-derived Polioviruses.\n\n'
                    )

                section_html += '</ul>'
                env_sections_html.append(section_html)

            if env_sections_html:
                run_html += '\n'.join(env_sections_html)

            # ENV Wild Poliovirus
            env_wpv_sections_html = []
            for wpv_type in ['WPV1', 'WPV2', 'WPV3']:
                env_wpv = envs.loc[(envs['classification'] == wpv_type) & (envs['SampleQC'] == 'Pass')]
                if env_wpv.empty:
                    continue

                wpv_found = True
                section_html = (
                    f'<p><b>Environmental samples detected as {wpv_type} (wild poliovirus) that can be reported:</b></p>\n<ul>'
                )
                text += f'\nEnvironmental samples detected as {wpv_type} (wild poliovirus) that can be reported:\n'

                for s in sorted(set(env_wpv['sample'].dropna().values)):
                    section_html += (
                        f'<li>{s}. <span class="muted">Immediately classified as '
                        f'<span class="hi-red">{wpv_type}</span> per GPEI guidelines.</span></li>\n'
                    )
                    text += f'•\t{s}\n'
                    text += f'Immediately classified as {wpv_type} per GPEI guidelines.\n\n'

                section_html += '</ul>'
                env_wpv_sections_html.append(section_html)

            if env_wpv_sections_html:
                run_html += '\n'.join(env_wpv_sections_html)
                
                
            # Minknow and Piranha statement
            try:
                minknow_ver = report['MinKNOWSoftwareVersion'].unique()[0]
            except:
                print('Tried to get minknow versions')
                print(report_name)
                print(report)
                minknow_ver = "Unknown"
                
            try:
                piranha_ver = report['AnalysisPipelineVersion'].unique()[0]
            except:
                print('Tried to get piranha versions')
                print(report_name)
                print(report)
                piranha_ver = "Unknown"
                
            # Number of negatives
            text += f'\nNumber of Negative EPIDs: {neg_epid_count.values[0]}\n'
            run_html += f'\n<p><b>Number of Negative EPIDs:</b> {neg_epid_count.values[0]}</p>'
            run_html += f"<p class='muted small'>MinKNOW {html_std.escape(str(minknow_ver))} &middot; Piranha {html_std.escape(str(piranha_ver))}</p>\n"

            run_html += '</div>'
            html_runs.append(run_html)

        # summary table
        total_pass = ddns_total_pass.classification.value_counts()
        total_sample_fail = ddns_total_sample_fail.classification.value_counts()

        total_table = pd.concat(
            [total_pass, total_sample_fail],
            axis=1, keys=['Pass', 'Sample Fail']
        ).fillna(0).astype(int).sort_index().reset_index(names=f'{report_mode} Classification')

        total_table['Run Fail'] = '-' 

        total_table_no_neg = total_table[total_table[f'{report_mode} Classification'] != 'Negative']
        run_fail_total = run_fail_sample_total

        total_row = pd.DataFrame([{
            f'{report_mode} Classification': 'Total',
            'Pass': int(total_table['Pass'].sum()),
            'Sample Fail': int(total_table['Sample Fail'].sum()),
            'Run Fail': run_fail_total
        }])

        total_row_nonneg = pd.DataFrame([{
            f'{report_mode} Classification': 'Total (Negatives excluded)',
            'Pass': int(total_table_no_neg['Pass'].sum()),
            'Sample Fail': int(total_table_no_neg['Sample Fail'].sum()),
            'Run Fail': '-'
        }])

        total_table = pd.concat([total_table, total_row, total_row_nonneg], ignore_index=True)

        text = (total_table.to_string(index=False, justify='left') + '\n') + text
        text = 'Summary count table for all runs\n' + text

        runs_html = ''.join(html_runs) 

        # Summary table
        summary_html = '<h2>Summary count table for all Runs</h2>' + total_table.to_html(index=False, classes="summary compact striped")

        # Vertical run index pills
        runs_index_html = ''
        if report_name_list:
            all_runs = []
            for n in passed_report_names:
                all_runs.append((n, "pass", None))
            for (n, reason) in failed_runs:
                all_runs.append((n, "fail", reason))

            # Sort by run name
            all_runs.sort(key=lambda x: x[0])

            # Render pills
            pills_html = ""
            for n, status, reason in all_runs:
                if status == "fail":
                    pills_html += (
                        f'<span class="pill failed" title="{html_std.escape(reason)}">'
                        f'{html_std.escape(n)} &middot; <strong>INVALID RUN:</strong> {html_std.escape(reason)}'
                        f'</span>'
                    )
                else:
                    pills_html += f'<span class="pill">{html_std.escape(n)}</span>'

            runs_index_html = (
                f'<div class="run-index">'
                f'<div class="muted small">Runs in this report:</div>'
                f'{pills_html}</div>'
            )

        # Title & file name
        if len(report_name_list) > 1:
            title_text = f"DDNS REPORT FOR RUNS {report_name_list[0]} TO {report_name_list[-1]}"
            html_file_output = f"{destination_path}/{report_mode}_report_{report_name_list[0]}_to_{report_name_list[-1]}.html"
        else:
            title_text = f"DDNS REPORT FOR RUN {report_name_list[0]}"
            html_file_output = f"{destination_path}/{report_mode}_report_{report_name_list[0]}.html"

        # Country/Lab
        country = (self.country_entry.text() or "").strip()
        lab = (self.lab_entry.text() or "").strip()

        subtitle_bits = []
        if country:
            subtitle_bits.append(html_std.escape(country))
        if lab:
            subtitle_bits.append(html_std.escape(lab))

        subtitle_html = ""
        if subtitle_bits:
            subtitle_html = f"""<div class="subtitle">{' <span class="dot">&middot;</span> '.join(subtitle_bits)}</div>"""

        # Title block
        title_html = f"""
        <header class="page-header">
        <h1 class="title">{html_std.escape(title_text)}</h1>
        {subtitle_html}
        </header>
        """

        ack = ("<p class='muted'>These data were produced using polio sequencing "
            "<a href='https://www.protocols.io/workspaces/poliovirus-sequencing-consortium/about'>Protocols</a> "
            "and analysis <a href='https://github.com/polio-nanopore/piranha'>software</a> developed by the "
            "<a href='https://polionanopore.org/about.html'>Polio Sequencing Consortium</a>.</p>")

        # theme and page wrapper
        html = f"""<html>
        <head>
        <meta charset="utf-8">
        <style>
        :root{{
            --ink:#111827; --muted:#6b7280; --brand:#0b5fff;
            --card:#f8fafc; --border:#e5e7eb; --accent:#eef2ff;
            --thead:#111827; --thead-text:#fff;
        }}
        html,body{{margin:0;padding:0;background:#fff;color:var(--ink);}}
        body{{
            font: 15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,"Apple Color Emoji","Segoe UI Emoji";
            max-width: 1100px; margin: 24px auto; padding: 0 16px;
        }}
        h1{{font-size:28px; margin: 0 0 16px;}}
        h2{{font-size:22px; margin: 28px 0 8px; border-bottom:1px solid var(--border); padding-bottom:6px;}}
        h3{{font-size:18px; margin: 20px 0 8px;}}
        p{{margin:10px 0;}}
        .muted{{ color: var(--muted); }}
        .small{{ font-size: 12px; }}
        mark{{ background: var(--accent); color:#b91c1c; padding:0 3px; border-radius:2px; }}

        /* Vertical run index pills */
        .run-index{{ display:flex; flex-direction:column; align-items:flex-start; gap:6px; margin: 8px 0 16px; }}
        .pill{{ display:inline-block; background:#fff; border:1px solid var(--border); padding:6px 12px; border-radius:999px; }}
        .pill.failed{{ background:#fee2e2; border-color:#fecaca; color:#991b1b; }}
        .run-name{{ color: var(--brand); }}

        /* Panel card */
        .panel-inner{{
            background: var(--card);
            border:1px solid var(--border);
            border-radius:12px;
            margin: 12px 0 18px;
            padding: 14px 16px 18px;
            box-shadow: 0 1px 2px rgba(0,0,0,.03);
        }}

        /* Highlighted red text */
        .hi-red {{ color:#b91c1c; font-weight:700; }}

        /* Tables */
        table{{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
        th, td{{ border:1px solid var(--border); padding:8px 10px; text-align:left; vertical-align:top; }}
        th{{ background:var(--thead); color:var(--thead-text); position:sticky; top:44px; z-index:5; }}
        tr:nth-child(even){{ background:#f9fafb; }}
        table.compact td, table.compact th{{ padding:6px 8px; }}
        table.striped tr:nth-child(even){{ background:#f6f7fb; }}
        table.summary tr:last-child td{{ font-weight:700; background:#dbeafe; }}
        table.summary {{ background: #f0f7ff; border: 1px solid #bfdbfe; }}
        table.summary th {{ background: #2563eb; color: #fff; }}

        /* Page header */
        .page-header {{ margin: 6px 0 14px; }}
        .title {{
        font-size: 34px;
        line-height: 1.2;
        margin: 0;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #0f172a; /* slate-900 */
        }}
        /* subtle accent underline */
        .title::after {{
        content: "";
        display: block;
        width: 72px;
        height: 4px;
        border-radius: 999px;
        margin-top: 8px;
        background: linear-gradient(90deg, var(--brand), #93c5fd);
        }}

        .subtitle {{
        margin-top: 6px;
        font-size: 15px;
        color: var(--muted);
        }}
        .subtitle .dot {{
        margin: 0 8px;
        opacity: .6;
        }}

        a{{ color:var(--brand); text-decoration:none; }}
        a:hover{{ text-decoration:underline; }}
        </style>
        </head>
        <body>
        {title_html}
        {runs_index_html}
        {summary_html}
        {runs_html}
        {ack}
        </body>
        </html>"""

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
        # Show bg_label again when cleared
        if hasattr(self.listbox_view, 'bg_label'):
            self.listbox_view.bg_label.show()

if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        prog = App()
        prog.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.error("Application initialization failed", exc_info=True)
        print(f"Application failed to start: {str(e)}")
        prog = App()
        prog.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.error("Application initialization failed", exc_info=True)
        print(f"Application failed to start: {str(e)}")

