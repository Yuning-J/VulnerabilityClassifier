# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2021 Yuning-Jiang - yuning.jiang17@gmail.com

import re
import requests
import zipfile
import os
from os import listdir
from os.path import isfile, join

#Download NVD data feeds in JSON format. 
def get_nvd_data():
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip",r.text):
        print(filename)
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
        filePath = "zipFile"
        if not os.path.exists(filePath):
            os.makedirs(filePath)
        with open("zipFile/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)

#Extract the JSON files from .zip files.
def unzip_data():
    files = [f for f in listdir("zipFile/") if isfile(join("zipFile/", f))]
    files.sort()
    for file in files:
        print("Opening: " + file)
        archive = zipfile.ZipFile(join("zipFile/", file), 'r')
        filePath = "jsonFile"
        if not os.path.exists(filePath):
            os.makedirs(filePath)
        with archive as f:
            f.extractall('jsonFile')

if __name__ == '__main__':
     get_nvd_data()
     unzip_data()
