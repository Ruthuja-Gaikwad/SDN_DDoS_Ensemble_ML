# SDN_DDoS_Ensemble_ML
Welcome to SDN_DDoS_Ensemble_ML, an advanced project enhancing DDoS attack detection and mitigation in Software Defined Networks (SDN). Using an ensemble online machine learning model, our approach effectively counters various DDoS threats, including low-rate and zero-day attacks, ensuring robust network security and performance.

Enhancing DDoS Attack Detection and Mitigation in SDN Using an Ensemble Online Machine Learning Model
This repository contains the implementation of the research work aimed at enhancing the detection and mitigation of Distributed Denial of Service (DDoS) attacks in Software Defined Networks (SDN) through an ensemble online machine learning model.


# Features
Ensemble Online Machine Learning Model: Adapts dynamically to new DDoS attack patterns.
High Detection Accuracy: Achieves a 99.2% detection rate, outperforming existing models on multiple benchmark datasets.
Dynamic Feature Selection: Continuously updates with relevant features to handle low-rate and zero-day DDoS attacks.
Comprehensive Evaluation: Validated using SDN simulations with Mininet and Ryu, and tested on datasets such as CICDDoS2019, InSDN, and KSL_NDD.


# Repository Structure
src/: Source code for the ensemble online machine learning model.
datasets/: Custom and benchmark datasets used for training and evaluation.
notebooks/: colab notebooks for data preprocessing, model training, and evaluation.
scripts/: Utility scripts for running simulations and experiments in SDN environments.


# Usage
Prepare the datasets by running the preprocessing scripts in the scripts directory.
Train the model using the notebooks provided in the notebooks directory.
Evaluate the model performance using the provided evaluation scripts and compare it with other benchmark models.


# Contributing
We welcome contributions to improve the project. Please fork the repository, create a new branch, and submit pull requests.
