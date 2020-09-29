# OneDrive File Restore Utility

This application was written to quickly restore files from version history based on a specific date in time that you can set in the config.yaml file. Any file that matches the encrypted file extension you set in the user interface will be checked leveraging Microsoft GraphAPI. These files will be validated for a version in the version history that has the highest version number but has a data prior to the date specified int he config.yaml file.

### Requirements

1. Python 3.7 or newer
2. install the dependencies `pip install -r requirements.txt`
3. Azure app registration must be created in conjunction with the file `Registering the OneDrive Restore Application in your Azure Organization.docx`
4. parameters collected during the app registration must be entered into the `config.yaml` file
5. update config.yaml file to have

### Getting started

1. start the app `python app.py`
2. open a browser to `http://localhost:5000`
3. authenticate with the user who's OneDrive you are wanting to restore
4. check the Drives link to ensure you are seeing successful connection to OneDrive
5. from the home page, click the `Restore My Drive` button
6. enter the parameter for encrypted file extension. for example `.89z8g`
7. select DEV or PROD mode and click `Start Now!`
8. Your restore job could take a while. Be patient!
9. a log file with the user email will be created on the local file system. This will have data for all files evaluated and the steps taken per file.

## create an app in Azure for OneDrive / GraphAPI

https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/app-registration?view=odsp-graph-online

## getting access tokens for Graph API

http://codematters.tech/getting-access-token-for-microsoft-graph-using-oauth-rest-api/
