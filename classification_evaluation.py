# -*- coding: utf-8 -*-

import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from attacksTests import WB_attack, BB_attack, ZK_attack
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
from sklearn.metrics import confusion_matrix
import pandas as pd

# for matplotlib graph
ID5_acc = []
ID5_F1 = []
ID5_TPR = []
ID5_FNR = []
C4_acc = []
C4_F1 = []
C4_TPR = []
C4_FNR = []
svm_acc = []
svm_F1 = []
svm_TPR = []
svm_FNR = []
KNN_acc = []
KNN_F1 = []
KNN_TPR = []
KNN_FNR = []


def train_and_evaluate(classifier, X_train, y_train, X_test, y_test):
    classifier.fit(X_train, y_train)
    predictions = classifier.predict(X_test)
    cm = confusion_matrix(y_test, predictions)
    tn, fp, fn, tp = cm.ravel()
    fnr = (fn / 1.0 / (fn / 1.0 + tp / 1.0))
    acc = accuracy_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    return acc, f1, recall, fnr


# Read the two CSV files
df1 = pd.read_csv("Report/Benign_Set.csv")
df2 = pd.read_csv("Report/Malicious_Set.csv")

# Create a single DataFrame to contain both of the DataFrames
df_concat = pd.concat([df1, df2], sort=False)
df_concat = df_concat.fillna(0)
df_concat.to_csv("Report/Concatenated_Set.csv", index=False)
# split the data into X and y
X = df_concat.drop(columns=['APK Name', 'Malicious'])
y = df_concat['Malicious']
# Split the data into train and test sets 80% train 20% test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print ("Traning set size: " + str(len(y_train)) + " The testing set size: " + str(len(y_test)))

classifiers = {'ID5 Decision Tree': DecisionTreeClassifier(criterion='entropy'),
               'C4.5 Decision Tree': DecisionTreeClassifier(criterion='gini'),
               'Linear SVM': SVC(kernel='linear'),
               'KNN': KNeighborsClassifier()}

for name, classifier in classifiers.items():
    acc, f1, recall, fnr = train_and_evaluate(classifier, X_train, y_train, X_test, y_test)
    # for matplotlib graph save the resualts of each classifier
    if name == 'ID5 Decision Tree':
        ID5_acc.append(acc)
        ID5_F1.append(f1)
        ID5_TPR.append(recall)
        ID5_FNR.append(fnr)
    elif name == 'C4.5 Decision Tree':
        C4_acc.append(acc)
        C4_F1.append(f1)
        C4_TPR.append(recall)
        C4_FNR.append(fnr)
    elif name == 'Linear SVM':
        svm_acc.append(acc)
        svm_F1.append(f1)
        svm_TPR.append(recall)
        svm_FNR.append(fnr)
    else:
        KNN_acc.append(acc)
        KNN_F1.append(f1)
        KNN_TPR.append(recall)
        KNN_FNR.append(fnr)
    print(name + ' Results')
    print("Accuracy: {:.2%}".format(acc))
    print("F1-score: {:.2%}".format(f1))
    print("TPR (True Positive Rate) = Recall: {:.2%}".format(recall))
    print("FNR (False Negative Rate): {:.2%}".format(fnr))
    print("\n")

print (
    "\n-------------------------------------------Zero Knowledge attack on Decision Tree,Linear SVM and KNN-------------------------------------------")
for name, classifier in classifiers.items():
    Zk_data = ZK_attack(X_test)
    # evaluate classifiers
    classifier_predictions = classifier.predict(Zk_data)
    cm = confusion_matrix(y_test, classifier_predictions)
    tn, fp, fn, tp = cm.ravel()
    # Calculate the false negative rate
    fnr = (fn / 1.0 / (fn / 1.0 + tp / 1.0)) / 1.0
    acc = accuracy_score(y_test, classifier_predictions)
    f1 = f1_score(y_test, classifier_predictions)
    # dt_precision = precision_score(y_test, dt_predictions)
    recall = recall_score(y_test, classifier_predictions)
    if name == 'ID5 Decision Tree':
        ID5_acc.append(acc)
        ID5_F1.append(f1)
        ID5_TPR.append(recall)
        ID5_FNR.append(fnr)
    elif name == 'C4.5 Decision Tree':
        C4_acc.append(acc)
        C4_F1.append(f1)
        C4_TPR.append(recall)
        C4_FNR.append(fnr)
    elif name == 'Linear SVM':
        svm_acc.append(acc)
        svm_F1.append(f1)
        svm_TPR.append(recall)
        svm_FNR.append(fnr)
    else:
        KNN_acc.append(acc)
        KNN_F1.append(f1)
        KNN_TPR.append(recall)
        KNN_FNR.append(fnr)
    print(name + ' Results')
    print("Accuracy: {:.2%}".format(acc))
    print("F1-score: {:.2%}".format(f1))
    print("TPR (True Positive Rate) = Recall: {:.2%}".format(recall))
    print("FNR (False Negative Rate): {:.2%}".format(fnr))
    print("\n")

print (
    "\n-------------------------------------------Black Box attack on Decision Tree,Linear SVM and KNN-------------------------------------------")
for name, classifier in classifiers.items():
    BB_data = BB_attack(X_test, classifier)
    # evaluate classifiers
    classifier_predictions = classifier.predict(BB_data)
    cm = confusion_matrix(y_test, classifier_predictions)
    tn, fp, fn, tp = cm.ravel()
    # Calculate the false negative rate
    fnr = (fn / 1.0 / (fn / 1.0 + tp / 1.0)) / 1.0
    acc = accuracy_score(y_test, classifier_predictions)
    f1 = f1_score(y_test, classifier_predictions)
    # dt_precision = precision_score(y_test, dt_predictions)
    recall = recall_score(y_test, classifier_predictions)
    if name == 'ID5 Decision Tree':
        ID5_acc.append(acc)
        ID5_F1.append(f1)
        ID5_TPR.append(recall)
        ID5_FNR.append(fnr)
    elif name == 'C4.5 Decision Tree':
        C4_acc.append(acc)
        C4_F1.append(f1)
        C4_TPR.append(recall)
        C4_FNR.append(fnr)
    elif name == 'Linear SVM':
        svm_acc.append(acc)
        svm_F1.append(f1)
        svm_TPR.append(recall)
        svm_FNR.append(fnr)
    else:
        KNN_acc.append(acc)
        KNN_F1.append(f1)
        KNN_TPR.append(recall)
        KNN_FNR.append(fnr)
    print(name + ' Results')
    print("Accuracy: {:.2%}".format(acc))
    print("F1-score: {:.2%}".format(f1))
    print("TPR (True Positive Rate) = Recall: {:.2%}".format(recall))
    print("FNR (False Negative Rate): {:.2%}".format(fnr))
    print("\n")

print (
    "\n -------------------------------------------White box attack on Decision Tree,Linear SVM and KNN-------------------------------------------")
for name, classifier in classifiers.items():
    WB_data = WB_attack(X_test, classifier, X_train)
    # evaluate classifiers
    classifier_predictions = classifier.predict(WB_data)
    cm = confusion_matrix(y_test, classifier_predictions)
    tn, fp, fn, tp = cm.ravel()
    # Calculate the false negative rate
    fnr = (fn / 1.0 / (fn / 1.0 + tp / 1.0)) / 1.0
    acc = accuracy_score(y_test, classifier_predictions)
    f1 = f1_score(y_test, classifier_predictions)
    # dt_precision = precision_score(y_test, dt_predictions)
    recall = recall_score(y_test, classifier_predictions)
    if name == 'ID5 Decision Tree':
        ID5_acc.append(acc)
        ID5_F1.append(f1)
        ID5_TPR.append(recall)
        ID5_FNR.append(fnr)
    elif name == 'C4.5 Decision Tree':
        C4_acc.append(acc)
        C4_F1.append(f1)
        C4_TPR.append(recall)
        C4_FNR.append(fnr)
    elif name == 'Linear SVM':
        svm_acc.append(acc)
        svm_F1.append(f1)
        svm_TPR.append(recall)
        svm_FNR.append(fnr)
    else:
        KNN_acc.append(acc)
        KNN_F1.append(f1)
        KNN_TPR.append(recall)
        KNN_FNR.append(fnr)
    print(name + ' Results')
    print("Accuracy: {:.2%}".format(acc))
    print("F1-score: {:.2%}".format(f1))
    print("TPR (True Positive Rate) = Recall: {:.2%}".format(recall))
    print("FNR (False Negative Rate): {:.2%}".format(fnr))
    print("\n")

############################################Graph Print########################################
# Define the labels for the x-axis
x_labels = ['Clean Set', 'Post ZK attack', 'Post BB attack', 'Post WB attack']

fig, ax = plt.subplots()

# Add the data to the graph as bar plots
bar_width = 0.1
x_pos = np.arange(len(x_labels))
ax.bar(x_pos, KNN_acc, width=bar_width, label='KNN')
ax.bar(x_pos + bar_width, ID5_acc, width=bar_width, label='ID5 Decision Tree')
ax.bar(x_pos + 2 * bar_width, svm_acc, width=bar_width, label='SVM')
ax.bar(x_pos + 3 * bar_width, C4_acc, width=bar_width, label='C4.5 Decision Tree')
ax.set_xticks(x_pos + bar_width / 2)
ax.set_xticklabels(x_labels)
# Add a legend to the graph
ax.legend()

# Add labels to the x and y axes
ax.set_xlabel('Data Set case')
ax.set_ylabel('Accuracy')
# Set the format of the tick labels on the y-axis to display as percentages
ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: '{:.0%}'.format(y)))
ax.set_ylim([0.6, 1.0])
# Display the graph
plt.show()

fig1, ax1 = plt.subplots()

# Add the data to the graph as bar plots
bar_width = 0.1
x_pos = np.arange(len(x_labels))
ax1.bar(x_pos, KNN_F1, width=bar_width, label='KNN')
ax1.bar(x_pos + bar_width, ID5_F1, width=bar_width, label='ID5 Decision Tree')
ax1.bar(x_pos + 2 * bar_width, svm_F1, width=bar_width, label='SVM')
ax1.bar(x_pos + 3 * bar_width, C4_F1, width=bar_width, label='C4.5 Decision Tree')
ax1.set_xticks(x_pos + bar_width / 2)
ax1.set_xticklabels(x_labels)
# Add a legend to the graph
ax1.legend()

# Add labels to the x and y axes
ax1.set_xlabel('Data Set case')
ax1.set_ylabel('F1-score')
# Set the format of the tick labels on the y-axis to display as percentages
ax1.yaxis.set_major_formatter(FuncFormatter(lambda y, _: '{:.0%}'.format(y)))
# Display the graph
plt.show()

fig2, ax2 = plt.subplots()

# Add the data to the graph as bar plots
bar_width = 0.1
x_pos = np.arange(len(x_labels))
ax2.bar(x_pos, KNN_TPR, width=bar_width, label='KNN')
ax2.bar(x_pos + bar_width, ID5_TPR, width=bar_width, label='ID5 Decision Tree')
ax2.bar(x_pos + 2 * bar_width, svm_TPR, width=bar_width, label='SVM')
ax2.bar(x_pos + 3 * bar_width, C4_TPR, width=bar_width, label='C4.5 Decision Tree')
ax2.set_xticks(x_pos + bar_width / 2)
ax2.set_xticklabels(x_labels)
# Add a legend to the graph
ax2.legend()

# Add labels to the x and y axes
ax2.set_xlabel('Data Set case')
ax2.set_ylabel('TPR (True Positive Rate)')
# Set the format of the tick labels on the y-axis to display as percentages
ax2.yaxis.set_major_formatter(FuncFormatter(lambda y, _: '{:.0%}'.format(y)))
# Display the graph
plt.show()

fig3, ax3 = plt.subplots()
# Add the data to the graph as bar plots
bar_width = 0.1
x_pos = np.arange(len(x_labels))
ax3.bar(x_pos, KNN_FNR, width=bar_width, label='KNN')
ax3.bar(x_pos + bar_width, ID5_FNR, width=bar_width, label='ID5 Decision Tree')
ax3.bar(x_pos + 2 * bar_width, svm_FNR, width=bar_width, label='SVM')
ax3.bar(x_pos + 3 * bar_width, C4_FNR, width=bar_width, label='C4.5 Decision Tree')
ax3.set_xticks(x_pos + bar_width / 2)
ax3.set_xticklabels(x_labels)
# Add a legend to the graph
ax3.legend()

# Add labels to the x and y axes
ax3.set_xlabel('Data Set case')
ax3.set_ylabel('FNR (False Negative Rate)')
# Set the format of the tick labels on the y-axis to display as percentages
ax3.yaxis.set_major_formatter(FuncFormatter(lambda y, _: '{:.0%}'.format(y)))
# Display the graph
plt.show()
