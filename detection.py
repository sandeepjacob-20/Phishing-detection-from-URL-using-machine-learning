import pickle
import feature_extraction as fe
features = []

url = input("Enter the URL : ")

features.append(fe.featureExtraction(url))

# loading the model to predict

loaded_model = pickle.load(open('model.pkl', 'rb'))

result = loaded_model.predict(features)
if result == 0:
    print("Safe")
else:
    print("Danger")