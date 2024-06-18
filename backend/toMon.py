from pymongo import MongoClient

def print_all_documents(collection_name):
    # החלף את ה-URI_STRING במחרוזת החיבור שלך
    URI_STRING = "mongodb+srv://adiitzko:<password>@cluster0.is6jut3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    
    # כאן יש להחליף את <password> בסיסמה שלך
    URI_STRING = URI_STRING.replace("<password>", "adiitz2004")
    
    client = MongoClient(URI_STRING)
    
    db = client.my_database  # החלף את my_database בשם בסיס הנתונים שלך
    collection = db[collection_name]
    
    # שליפת כל המסמכים באוסף
    documents = collection.find()
    
    # הדפסת כל המסמכים
    for document in documents:
        print(document)

# קריאת הפונקציה
print_all_documents("users")  # החלף את "users" בשם האוסף שלך
