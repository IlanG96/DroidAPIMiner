import math
import random

import numpy as np


# "zero-knowledge" attack:
# no knowledge about the classifier being used,
# randomly swaps pairs of features in the test files in the hope
# that this will cause the classifier to misclassify them.
def ZK_attack(test_data):
    attacked_data = test_data.copy()
    for i in range(attacked_data.shape[0]):
        for j in range(attacked_data.shape[1]/2):
            ind1 = random.randint(0, attacked_data.shape[1] - 1)
            ind2 = random.randint(0, attacked_data.shape[1] - 1)
            tmp = attacked_data.iloc[i, ind1]
            attacked_data.iloc[i, ind1] = attacked_data.iloc[i, ind2]
            attacked_data.iloc[i, ind2] = tmp
    return attacked_data


# "black-box" attack
# have access to the classifier being used,
# but not the internal workings of it,
# try to modify the test files in a way that will cause the classifier to misclassify them.
def BB_attack(test_data, model):
    attacked_data = test_data.copy()
    for i in range(attacked_data.shape[0]):
        for j in range(attacked_data.shape[1]/2):
            # Generate random indices to modify
            ind1 = random.randint(0, attacked_data.shape[1] - 1)
            ind2 = random.randint(0, attacked_data.shape[1] - 1)
            # change the values
            attacked_data.iloc[i, ind1] = 1 if attacked_data.iloc[i, ind1] == 0 else 0
            attacked_data.iloc[i, ind2] = 1 if attacked_data.iloc[i, ind2] == 0 else 0
            # Predict using the classifier
            pred = model.predict(attacked_data.iloc[i].values.reshape(1, -1))
            # If the prediction is not 1 (malicious), break out of the loop
            if pred != 1:
                break
    return attacked_data


# "white-box" attack,
# have access to both the classifier and the training data being used,
#  try to find a sample from the training set that is similar to the test files
#  and hope that the classifier will classify them as the same class.
def WB_attack(test_data, clf, X_train):
    for i in range(1500):
        # Randomly select the same number of rows as the test files dataset
        samp = X_train.iloc[np.random.choice(X_train.shape[0], test_data.shape[0], replace=False)]
        pred = clf.predict(samp)
        # Check if the average prediction is not of the sample is under 0.19
        if np.mean(pred) < 0.19:
            return samp
    return test_data
