# RunReporter
This is a repository for Polio Sequencing Consortium Run Reporter app development. The app generates an aggregate report from DDNS/Isolate run reports.

## Interface
<p align="center">
<img src="misc/app_interface.png" alt="Interface" height=70% width=70%>
</p>

## Installation
Go to the releases page and download the latest release, this will be a single executable file. For now there is only a Windows version of the app. You might need to allow the executable through your firewall if it does not run the first time.

## Usage
The User firstly selects the destination where the report is saved to and then the User can drag the detailed run reports into the dropbox. The User will then click the Generate button to run the app. A message will let you know if the app worked successfully and show you the output file name. The output file name is made using the lowest and highest run number and the chosen report mode e.g. {mode}_{lowest report}_to_{highest_report}.html.

The User can choose reporting modes with selection box in the top left, by default it is DDNS. The DDNS mode will display both Sabin and VDPV samples information such as classification and EPID. The Isolate mode, will only display sample information for the VDPVs. Both Modes will display summary counts of all classifications for all the runs supplied and for the individual runs.

The app will handle a few errors such as no destination / no input file chosen,missing columns, but the app has a general error handler that will display the error and write to log file called "app_error.log" at the chosen destination output. This log will have more details about the error for debugging purposes; this won't be overwritten but logs will continually be added until the file is 5Mb in size and will delete the earliest logs. 

If the wrong file was chosen, use the clear button to clear the dropbox. If the app has run successfully, it will automatically clear the dropbox and the destination path will never be cleared.

The copy button allows the users to copy the simple text version of the report. 

## Inputs
The detailed run reports should be completed by the technical team lead before this point, but the app only requires these columns to completed:

- sample
- [DDNS|Isolate]classification
- EpidNumber
- [Run|Sample]QC
- ToReport
- AnalysisPipelineVersion
- MinKNOWSoftwareVersion
- EmergenceGroupVDPV[1|2|3]
- Piranha columns

The user can supply as many reports as they want to the app. The app will check for empty information such as EpidNumber and warn the user. The two software version will be filled in as missing in the output if missing and the EmergenceGroup of a VDPV will be filled in as LINEAGE_HERE if missing as well. Please return to those reports and will the information and run the app again.

The filenames for the reports are expected to be in the format YYYYMMDD_RUNNUMBER_detailed_run_report.csv, e.g. 20250528_001_detailed_run_report.csv. This won't prevent the app from working but will mess up the output filename.

## Output

The main output of app is the HTML report described above. Below is an example:


The app also has a small text window that will show a simplified version of the report, useful if want to check the output at a glance or copy it using the copy button. The text can be put into an email for example.
