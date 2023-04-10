require 'openssl'


#converts an int to a binary string
def int_to_binary(integer)
    integer.to_s(2)
end

#converts a normal string to a binary string
def string_to_binary(str)
    str.bytes.map{|d| d.to_s(2)}.map{|b| b.rjust(8, '0')}.join
end

#converts normal string to array of ints
def binary_string_to_int_arr(start_byte, end_byte, arr)
    
    result = []
    
    for i in start_byte..end_byte do
        result << arr[8*i..8*i+7].to_i(2)
    end

    result
end

#for getting specific values to tamper the ciphertext with to control 
#the padding bytes of the corresponding plain text
def get_tampered_values(padding_byte_val, known_values)
    tampered_values = []

    for i in 0..(known_values.length()-1) do
        value_to_xor = known_values[i].to_i(10)
        tampered_values << int_to_binary((value_to_xor ^ padding_byte_val))
    end

    tampered_values
end

#apply the tampered values to the known ciphertext
def tamper_ciphertext(binary_cipher_text, new_byte_val, byte_to_edit)
    
    #add leading zeros to make sure 8 bits used
    zeros_to_front = 8 - new_byte_val.length()

    for i in 0..7 do
        if i < zeros_to_front
            binary_cipher_text[byte_to_edit*8 + i] = "0"
        else
            binary_cipher_text[byte_to_edit*8+i] = new_byte_val[i-zeros_to_front]
        end
    end
    
end


use_case = ARGV[1]

#for querying the oracle to test for padding error
if use_case == "query"
    



    #define data to encrypt, key, and iv
    data = "sixteenbytesplzzsixteenbytesplzzsixteenbytes"
    key = "the most secret!"
    iv = "also very secret"

    #perform the encryption to get ciphertext
    cipher = OpenSSL::Cipher::AES.new(128, :CBC)
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv

    encrypted = cipher.update(data) + cipher.final


    #convert ciphertext to binary for per byte tampering
    binary_cipher_text = string_to_binary(encrypted)


    #fill in what we know about I3 
    known_values = File.read("known_values.txt").split

   
    #calculate necessary tampered values, the first 
    #argument specificies the desired value in the 
    #plaintext block
    tampered_values = get_tampered_values(known_values.length() + 1, known_values)



    # put tampered_values in
    for i in 0..(known_values.length()-1) do
        tamper_ciphertext(binary_cipher_text, tampered_values[i], 31-i)
    end

    #receive user input for brute force
    byte_to_edit = 31-known_values.length()
    new_byte_val = int_to_binary(ARGV[0].to_i)
    # new_byte_val = int_to_binary(216)
    tamper_ciphertext(binary_cipher_text, new_byte_val, byte_to_edit)


    #convert tampered ciphertext to format appropriate for decryption
    reconstructed_string_ciphertext = binary_cipher_text.scan(/.{8}/).map{|m| m.to_i(2)}.map{|n| n.chr}.join



    #perform the decryption
    decipher = OpenSSL::Cipher::AES.new(128, :CBC)
    decipher.decrypt
    decipher.key = key
    decipher.iv = iv

    #here is where an error will be thrown if the padding is wrong (the oracle)
    plain = decipher.update(reconstructed_string_ciphertext) + decipher.final



#for testing that inferred padding byte is the value we expected
elsif use_case == "edge"

    #define data to encrypt, key, and iv
    data = "sixteenbytesplzzsixteenbytesplzzsixteenbytes"
    key = "the most secret!"
    iv = "also very secret"


    #perform the encryption
    cipher = OpenSSL::Cipher::AES.new(128, :CBC)
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv

    encrypted = cipher.update(data) + cipher.final


    binary_cipher_text = string_to_binary(encrypted)


    #tamper the ciphertext
    tamper_ciphertext(binary_cipher_text, int_to_binary(15), 1)



    #fill in what we know about I3 
    known_values = File.read("known_values.txt").split



    #calculate necessary tampered values, the first 
    #argument specificies the desired value in the 
    #plaintext block
    tampered_values = get_tampered_values(known_values.length() + 1, known_values)


    # put tampered_values in
    for i in 0..(known_values.length()-1) do
        tamper_ciphertext(binary_cipher_text, tampered_values[i], 31-i)
    end

    #receive user input for brute force
    byte_to_edit = 31-known_values.length()
    new_byte_val = int_to_binary(ARGV[0].to_i)
    # new_byte_val = int_to_binary(216)
    tamper_ciphertext(binary_cipher_text, new_byte_val, byte_to_edit)


    #test edge case except for when index is 0
    if 31-known_values.length() - 1 >= 0
        #receive user input for brute force
        byte_to_edit = 31-known_values.length() - 1
        new_byte_val = int_to_binary(0)
        # new_byte_val = int_to_binary(216)
        tamper_ciphertext(binary_cipher_text, new_byte_val, byte_to_edit)
    end

    #convert tampered ciphertext to value appropriate for decryption
    reconstructed_string_ciphertext = binary_cipher_text.scan(/.{8}/).map{|m| m.to_i(2)}.map{|n| n.chr}.join



    #perform the decryption
    decipher = OpenSSL::Cipher::AES.new(128, :CBC)
    decipher.decrypt
    decipher.key = key
    decipher.iv = iv

    #here is where an error will be thrown if the padding is wrong (the oracle)
    plain = decipher.update(reconstructed_string_ciphertext) + decipher.final



elsif use_case == "decrypt"

    #define data to encrypt, key, and iv
    data = "sixteenbytesplzzsixteenbytesplzzsixteenbytes"
    key = "the most secret!"
    iv = "also very secret"

    #perform encryption to get ciphertext
    cipher = OpenSSL::Cipher::AES.new(128, :CBC)
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv

    encrypted = cipher.update(data) + cipher.final

    #convert to int array so we can xor and decrypt using the values returned by attack
    int_arr_ecnrypted = binary_string_to_int_arr(16, 31, string_to_binary(encrypted))

    known_values = File.read("known_values.txt").split

    decrypted_bytes = []

    #decrypt using attack values (Note we aren't using the ruby decrypt function)
    for i in 0..known_values.length() do

        decrypted_bytes <<  (known_values[i].to_i ^ int_arr_ecnrypted[15-i].to_i)

    end

    #print proof of concept result "sixteenbytes" is printed
    puts decrypted_bytes.pack('c*')[0..15].reverse()
    

end




