# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2021 Yuning-Jiang - yuning.jiang17@gmail.com

import json
import csv
import pandas as pd
from os import listdir
from os.path import join

def create_nvd_dict(year):
    filename = join("jsonFile/nvdcve-1.1-" + str(year) + ".json")
    #print("Opening: " + filename)
    with open(filename, encoding="utf8") as json_file:
        cve_dict = json.load(json_file)
    return(cve_dict)

def generate_CVSSV3csv_for_training():
    list = listdir("jsonFile/")
    number_files = len(list)
    for year in range(2002,2002 + number_files):
        year_in_string = str(year)
        cve_dict = create_nvd_dict(year)
        fileName = 'NVD_'+ year_in_string + '_CVSSV3_train.csv'
        with open('trainCVSSV3/' + fileName, 'w', newline='') as f_output:
            csv_output = csv.writer(f_output)
            csv_output.writerow(['CVE_ID', 'PublishTime','ModifyTime','Report','CVSSV3','AttackVector','AttackComplexity','PrivilegesRequired',
                             'UserInteraction','Scope','ConfidentialityImpact','IntegrityImpact','AvailabilityImpact'])
            for item in cve_dict['CVE_Items']:
                cve_id = item['cve']['CVE_data_meta']['ID']
                report = item['cve']['description']['description_data'][0]['value']
                publish = item['publishedDate']
                modify = item['lastModifiedDate']
                if not report.find("**REJECT**"):
                    continue
                if 'baseMetricV3' not in item['impact']:
                    continue
                elif 'baseMetricV3' in item['impact']:
                    cvssv3_base_score = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                    attackVector = item['impact']['baseMetricV3']['cvssV3']['attackVector']
                    attackComplexity = item['impact']['baseMetricV3']['cvssV3']['attackComplexity']
                    privilegesRequired = item['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
                    userInteraction = item['impact']['baseMetricV3']['cvssV3']['userInteraction']
                    scope = item['impact']['baseMetricV3']['cvssV3']['scope']
                    confidentialityImpact = item['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
                    integrityImpact = item['impact']['baseMetricV3']['cvssV3']['integrityImpact']
                    availabilityImpact = item['impact']['baseMetricV3']['cvssV3']['availabilityImpact']

                    csv_output.writerow([cve_id, publish, modify,report, cvssv3_base_score,
                                 attackVector, attackComplexity, privilegesRequired, userInteraction,
                                 scope, confidentialityImpact, integrityImpact, availabilityImpact])

def generate_CombinedFile():
    generate_CVSSV3csv_for_training()
    list = listdir("trainCVSSV3/")
    number_files = len(list)-1
    dict = []
    dict_of_reports = {}
    for year in range(2002,2002 + number_files):
        year_in_string = str(year)
        file_name = 'NVD_'+ year_in_string + '_CVSSV3_train.csv'
        dict_of_reports[year_in_string] = []
        dict_of_reports[year_in_string] = pd.read_csv("trainCVSSV3/" + file_name)
        dict.append(dict_of_reports[year_in_string])
    df = pd.concat(dict, ignore_index=True)
    return df
