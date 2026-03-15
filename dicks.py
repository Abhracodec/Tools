import pprint
passwords = {"ram":"123","jam":"4567", "abhra":"Abhra12345", "tom":"9900887"}
print("The password of abhra is "+ passwords["abhra"])
print(passwords.keys())
print(passwords.values()) 
print(passwords.items() ) 
print(passwords.get("om" , "nei")) 
passwords.setdefault("bantu","kalu")
passwords.setdefault("bantu","panu") #wont change here cuz alredy exists
print(passwords.items() ) 


message = "I love kali linuz so much but imma cuck it and use arch black soon aff"
count_words={}
for  character in message:
    count_words.setdefault(character,0) #changes only once the 1st time a char appear in the dict
    count_words[character]=count_words[character]+1
database=pprint.pformat(count_words)
print(database)