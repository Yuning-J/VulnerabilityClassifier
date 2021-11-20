# Software is free software released under the "GNU General Public License v3.0"
# Copyright (c) 2021 Yuning-Jiang - yuning.jiang17@gmail.com

import re
import numpy as np
import unicodedata
import logging
import pickle
from generateTrainingData import generate_CombinedFile
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import CountVectorizer,TfidfVectorizer

def pre_process(text):
    # lowercase
    text=text.lower()
    #remove tags
    text=re.sub("<!--?.*?-->","",text)
    # remove special characters and digits
    text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('utf-8', 'ignore')
    text= re.sub("(\\d|\\W)+"," ",text)
    text = re.sub('[^a-zA-z0-9\s]', '', text)
    return text

def _reciprocal_rank(true_labels: list, machine_preds: list):
    """Compute the reciprocal rank at cutoff k"""
    # add index to list only if machine predicted label exists in true labels
    tp_pos_list = [(idx + 1) for idx, r in enumerate(machine_preds) if r in true_labels]
    rr = 0
    if len(tp_pos_list) > 0:
        # for RR we need position of first correct item
        first_pos_list = tp_pos_list[0]
        # rr = 1/rank
        rr = 1 / float(first_pos_list)
    return rr

def compute_mrr_at_k(items:list):
    """Compute the MRR (average RR) at cutoff k"""
    rr_total = 0
    for item in items:
        rr_at_k = _reciprocal_rank(item[0],item[1])
        rr_total = rr_total + rr_at_k
        mrr = rr_total / 1/float(len(items))
    return mrr

def collect_preds(Y_test,Y_preds):
    """Collect all predictions and ground truth"""
    pred_gold_list=[[[Y_test[idx]],pred] for idx,pred in enumerate(Y_preds)]
    return pred_gold_list

def compute_accuracy(eval_items:list):
    correct=0
    total=0
    for item in eval_items:
        true_pred=item[0]
        machine_pred=set(item[1])
        for cat in true_pred:
            if cat in machine_pred:
                correct+=1
                break
    accuracy=correct/float(len(eval_items))
    return accuracy

def get_stop_words(stop_file_path):
    """load stop words """
    with open(stop_file_path, 'r', encoding="utf-8") as f:
        stopwords = f.readlines()
        stop_set = set(m.strip() for m in stopwords)
        return frozenset(stop_set)
#load a set of stop words
stopwords=get_stop_words("src/stopwords.txt")
logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)

def extract_features(df,field,training_data,testing_data,type="binary"):
    """Extract features using different methods"""
    logging.info("Extracting features and creating vocabulary...")
    if "binary" in type:
        # BINARY FEATURE REPRESENTATION
        cv= CountVectorizer(binary=True, max_df=0.95)
        cv.fit_transform(training_data[field].apply(lambda x:pre_process(x)).tolist())
        train_feature_set=cv.transform(training_data[field].apply(lambda x:pre_process(x)).tolist())
        test_feature_set=cv.transform(testing_data[field].apply(lambda x:pre_process(x)).tolist())
        return train_feature_set,test_feature_set,cv
    elif "counts" in type:
        # COUNT BASED FEATURE REPRESENTATION
        cv= CountVectorizer(binary=False, max_df=0.95)
        cv.fit_transform(training_data[field].apply(lambda x:pre_process(x)).tolist())
        train_feature_set=cv.transform(training_data[field].apply(lambda x:pre_process(x)).tolist())
        test_feature_set=cv.transform(testing_data[field].apply(lambda x:pre_process(x)).tolist())
        return train_feature_set,test_feature_set,cv
    else:
        # TF-IDF BASED FEATURE REPRESENTATION
        tfidf_vectorizer=TfidfVectorizer(smooth_idf=True,use_idf=True, max_df=0.95)
        tfidf_vectorizer.fit_transform(training_data[field].apply(lambda x:pre_process(x)).tolist())
        train_feature_set=tfidf_vectorizer.transform(training_data[field].apply(lambda x:pre_process(x)).tolist())
        test_feature_set=tfidf_vectorizer.transform(testing_data[field].apply(lambda x:pre_process(x)).tolist())
        return train_feature_set,test_feature_set,tfidf_vectorizer

def get_top_k_predictions(model,X_test,k):
    # get probabilities instead of predicted labels, since we want to collect top 3
    probs = model.predict_proba(X_test)
    # GET TOP K PREDICTIONS BY PROB - note these are just index
    best_n = np.argsort(probs, axis=1)[:,-k:]
    # GET CATEGORY OF PREDICTIONS
    preds=[[model.classes_[predicted_cat] for predicted_cat in prediction] for prediction in best_n]
    preds=[ item[::-1] for item in preds]
    return preds

def train_model(df,field,feature_rep,top_k,label):
    logging.info("Starting model training for "+label+"...")
    # GET A TRAIN TEST SPLIT (set seed for consistent results)
    training_data, testing_data = train_test_split(df,random_state = 2000,test_size=0.25)
    # GET LABELS
    if 'AttackVector' in label:
        Y_train=training_data['AttackVector'].values
        Y_test=testing_data['AttackVector'].values
        classes = ['NETWORK','ADJACENT_NETWORK','LOCAL','PHYSICAL']
    elif 'AttackComplexity' in label:
        Y_train=training_data['AttackComplexity'].values
        Y_test=testing_data['AttackComplexity'].values
        classes = ['HIGH','LOW']
    elif 'UserInteraction' in label:
        Y_train=training_data['UserInteraction'].values
        Y_test=testing_data['UserInteraction'].values
        classes = ['REQUIRED','NONE']
    elif 'PrivilegesRequired' in label:
        Y_train=training_data['PrivilegesRequired'].values
        Y_test=testing_data['PrivilegesRequired'].values
        classes = ['HIGH','LOW','NONE']
    elif 'Scope' in label:
        Y_train=training_data['Scope'].values
        Y_test=testing_data['Scope'].values
        classes = ['CHANGED','UNCHANGED']
    elif 'ConfidentialityImpact' in label:
        Y_train=training_data['ConfidentialityImpact'].values
        Y_test=testing_data['ConfidentialityImpact'].values
        classes = ['HIGH','LOW','NONE']
    elif 'IntegrityImpact' in label:
        Y_train=training_data['IntegrityImpact'].values
        Y_test=testing_data['IntegrityImpact'].values
        classes = ['HIGH','LOW','NONE']
    elif 'AvailabilityImpact' in label:
        Y_train=training_data['AvailabilityImpact'].values
        Y_test=testing_data['AvailabilityImpact'].values
        classes = ['HIGH','LOW','NONE']
    # GET FEATURES
    X_train,X_test,feature_transformer=extract_features(df,field,training_data,testing_data,type=feature_rep)
    # INIT LOGISTIC REGRESSION CLASSIFIER
    logging.info("Training a Logistic Regression Model...")
    scikit_log_reg = LogisticRegression(verbose=1, solver='liblinear',random_state=0, C=5, penalty='l2',max_iter=1000)
    model=scikit_log_reg.fit(X_train,Y_train)

    # GET TOP K PREDICTIONS
    preds=get_top_k_predictions(model,X_test,top_k)

    # GET PREDICTED VALUES AND GROUND TRUTH INTO A LIST OF LISTS - for ease of evaluation
    eval_items=collect_preds(Y_test,preds)

    # GET EVALUATION NUMBERS ON TEST SET -- HOW DID WE DO?
    logging.info("Starting evaluation...")
    accuracy=compute_accuracy(eval_items)
    mrr_at_k=compute_mrr_at_k(eval_items)
    logging.info("Done training and evaluation for "+label+".")

    return model,feature_transformer

def trainModel(data, label):
    field='Report'
    feature_rep='tfidf'
    top_k=1
    model, transformer = train_model(data,field,feature_rep,top_k,label)
    return model, transformer

def train_cvss_model(df):
    model = {}
    transformer = {}
    label_list = ['AttackVector','AttackComplexity','UserInteraction','PrivilegesRequired','Scope','ConfidentialityImpact','IntegrityImpact','AvailabilityImpact']
    logging.info("Starting training and evaluation for all CVSS V3 models")
    for idx in range(8)[0:]:
        var = label_list[idx]
        model[var], transformer[var] = trainModel(df, var)
        pickle.dump(transformer[var], open('trainedModel/transformer' + var + '.pickle', 'wb'))
        pickle.dump(model[var], open('trainedModel/model' + var + '.pickle', 'wb'))
    logging.info("Done training and evaluation for all CVSS V3 models.")

if __name__ == '__main__':
    df = generate_CombinedFile()
    df = df[~df['Report'].str.contains('REJECT')]
    train_cvss_model(df)
