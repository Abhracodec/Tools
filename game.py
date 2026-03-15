#index = single value , slice ":"= list of values 
list = ["cat" , "rat", "bat" , "fat" , "mat" , "chat"]
new = list[1:]
print(list)
print(new)

list.insert(2, "pokpok")
print(list)
list.remove("fat")
print(list)

list.sort()
print(list)

for i in range  (len(list)):
    print(str(i)+ " is the index of "+ list[i])
print ("The index of mfking cat is "+ str(list.index("cat")))