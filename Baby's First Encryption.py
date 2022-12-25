# Probabilistic Cypher Encryption V1
# Jermu Hautsalo 25.12.2022
# Notable functions in this script: generate_key(), encrypt(message, key), decrypt(message, key).

from random import randint, shuffle

# Data (text) to be cyphered (hexadecimal) probabilistically into a number (3) of values. These values and probabilities generate the cypher private key.
# Example cypher private key with a cypher split count of three and a hexadecimal numeral system: A = 00 (50%), FF (35%), 6A (15%).
# Example articulation: for 50% of the time 'A' appears in the data as '00', 35% of the time as 'FF' and 15% as '6A'
# The key can then be checked for both the cypher as well as the expected range of occurrence of 'A'.

# Below is a 80-character-long string containing all encryptable characters in this funtion.

alphanumerics = """0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz .,!?-$%"'#@:;/_()"""

# Below is the list of 256 hexadecimal values for the cypher private key. The generic variable objects are contained within a function to avoid being referenced.

def hex_list():
    lst = []
    for index in range(256):
        lst.append(hex(index))
    lst[0] = "0x00"; lst[1] = "0x01"; lst[2] = "0x02"; lst[3] = "0x03"; lst[4] = "0x04"; lst[5] = "0x05"; lst[6] = "0x06"; lst[7] = "0x07"
    lst[8] = "0x08"; lst[9] = "0x09"; lst[10] = "0x0a"; lst[11] = "0x0b"; lst[12] = "0x0c"; lst[13] = "0x0d"; lst[14] = "0x0e"; lst[15] = "0x0f"
    hexvalues = []
    for index in range(256):
        temp = lst[index]
        hexvalues.append(temp[2:4])
    return hexvalues

# Definition of the cypher key generation funtion below.
# For each character are assigned three hex values, known as common, uncommon and rare.
# This function must check for available hex values and assign them, so they cannot be twice assigned.
# This function must check for unassigned
# This function must return the cypher as a list of tuples, each containing the common, uncommon and rare cyphers, their corresponding probablilistic ranges and any invalid/unused cyphers.

def generate_key():
    cypher_private_key = []
    new_cypher = hex_list()
    shuffle(new_cypher)
    rare_probability = randint(5, 15)
    uncommon_probability = randint(16, 35)
    common_probability = 100 - uncommon_probability - rare_probability
    probability_tuple = (common_probability, uncommon_probability, rare_probability)
    cypher_private_key.append(probability_tuple)
    for index in range(80):
        common = new_cypher[0] 
        uncommon = new_cypher[1]
        rare = new_cypher[2]
        tuple1 = (common, uncommon, rare)
        cypher_private_key.append(tuple1)
        del new_cypher[0:3]
    # Note to self: try converting the remaining junk into a tuple in order to fix the corrupt decryption. Edit: made no apparent difference.
    new_cypher_tuple = tuple(i for i in new_cypher)
    return new_cypher_tuple, cypher_private_key
    # In this case the returned new_cypher_tuple is actually the list of unused hex values.

# The cypher private key is then used to encrypt and decrypt a string or message. Note that the key must exist outside of the function for decryption to maintain relevance.

def encrypt(message, key):
    encrypted_message = ""
    for character in message:
        if character in alphanumerics:
            rarity = randint(1,100)
            alpha_index = alphanumerics.index(character)
            if rarity < key[1][0][2]:
                encrypted_message += key[1][alpha_index+1][2]
            elif rarity < key[1][0][1]:
                encrypted_message += key[1][alpha_index+1][1]
            else: encrypted_message += key[1][alpha_index+1][0]
        # # Note to self: here is the encryption bloating code:
        # crit_chance = randint(1,16)
        # crit_dmg = key[0][randint(1,(len(key[0])-1))]
        # if crit_chance >= 15: encrypted_message += crit_dmg
        # # Note to self: its addition/removal appears to corrupt the message.
    return encrypted_message

# Encrypted messages are checked against the probability of the rarity of the hex value and decrypted using the cypher.

def decrypt(encrypted_message, key):
    decrypted_message = ""
    message_as_list = []
    count = 0
    probability_inconsistency = False
    # Checking for probability inconsistencies suggestive of message tampering.
    for cypher in key[1][1:]:
        if message_as_list.count(cypher[0]) > message_as_list.count(cypher[1]) and message_as_list.count(cypher[0]) > message_as_list.count(cypher[2]):
            probability_inconsistency = True
            decrypted_message += "**"
    # Breaking the string down into a more easily parsable list.
    for character in encrypted_message:
        count += 1
        if count % 2 == 0:
            message_as_list.append(encrypted_message[(count - 2):count])
    # Removing the junk hex values from the 'critical hit' system.
    for hexvalue in message_as_list:
        if hexvalue in key[0]:
            message_as_list.remove(hexvalue)
        else:
            # The actual decryption script.
            for cypher in key[1][1:]:
                for hex in cypher:
                    if hex == hexvalue: decrypted_message += alphanumerics[key[1].index(cypher) - 1]
    # Again, notifying of potential probability inconsistencies.
    if probability_inconsistency == True: decrypted_message += "**"
    return decrypted_message

# The following is script to test the functions.

# new_key = generate_key()
# # message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# message = "Tonight, for dinner, I will be eating the leftover rice noodle with mock duck that was left over from Christmas. I am famished from this coding exercise today!"
# new_encrypted_message = encrypt(message, new_key)
# print(new_key)
# print(new_key[1][0])
# print(new_key[1][11])
# print(new_encrypted_message)
# new_decrypted_message = decrypt(new_encrypted_message, new_key)
# print(new_decrypted_message)
# message_into_list = []
# count = 0
# for character in new_encrypted_message:
#     count += 1
#     if count % 2 == 0:
#         message_into_list.append(new_encrypted_message[(count - 2):count])
# crit_enabled = False
# for junk in new_key[0]:
#     if junk in message_into_list: crit_enabled = True
# print("Critical hits enabled:", crit_enabled)