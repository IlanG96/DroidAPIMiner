#!/usr/bin/env python
# -*- coding: utf-8 -*-
from dataflowanalysis import *
from external_api import *
import os
import csv


# all external api calls and data flow analysis
def result(x):
    """
    param x: an apk file
    :return:  a list of api_calls and data_flow_results
    """
    print("------------- Now working on " + x + " ----------------")
    return get_api_calls(x) + data_flow_result(x)


# Create a list to store the data
data = []

# Create a list to store the column names (API calls)
columns = ["Malicious"]
counter = 1
# Iterate through the APK files in the test_apk directory
for apk in os.listdir("test_apk"):
    apk_path = os.path.join("test_apk", apk)
    apk_name = os.path.basename(apk_path).rstrip(".apk")
    try:
        api_calls = result(apk_path)
        # Create a dictionary to store the row data
        row = {'APK Name': apk_name, "Malicious": 0}  # If you working on a malicous set change it to 1
        # Iterate through the API calls
        for api_call in api_calls:
            # If the API call is not in the columns list, add it
            if api_call not in columns:
                columns.append(api_call)
            # Add a value of 1 in the cell where the APK name and the API call intersect
            row[api_call] = 1
        # Add the row data to the data list
        data.append(row)
        print(str(counter) + "------------- Finished working on " + apk_path + " ----------------")
        counter += 1
    except:
        print("Failed getting results of " + apk_name)
        continue

# Iterate through the data and add 0 for missing API calls in each row
for row in data:
    for column in columns:
        if column not in row:
            row[column] = 0

# Write the data to a CSV file change the csv name according to you files
with open('Report/Benign_Set.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=['APK Name'] + columns)
    writer.writeheader()
    for row in data:
        writer.writerow(row)

##Original code
# for apk in os.listdir("test_apk"):
#     # print(apk)
#     apk_path = os.path.join("test_apk",apk)
#     print(apk_path)
#     print(os.path.basename(apk_path).rstrip(".apk"))
#     apk_name = os.path.basename(apk_path).rstrip(".apk")
#     result_dir = "Report/" + apk_name +  ".txt"
#     with open(result_dir ,"w+") as f:
#         for i in result(apk_path):
#             f.write(str(i) + "\n")
#     print(result(apk_path))
