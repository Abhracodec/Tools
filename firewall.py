def prediction (age):
    print ("you will be " + str(age + 1) + " next year")
    def_scope = 16
    print ("this is under prediction"+ str(def_scope))

def intro(name, age): #parametres = variables 
    print ("Hello", name)
    print ("You are", age, "years old")
    print ("your name has " + str(len(name)) +" letters in it")
    prediction (23) #nested function call
    def_scope = 160
    print ("this is under intro"+ str(def_scope))

intro("aman" , 23) #arguments = values

def vote_check():
    print ("enter your age")
    try:
        age_check = input()
        if int(age_check) >= 18:
            print("eligible")
        else:
            print("not eligible")
    except ValueError:
        print("Please enter a number fuckass")

vote_check()



