require 'openssl'


#converts an int to a binary string
def int_to_binary(integer)
    integer.to_s(2)
end

#converts a normal string to a binary string
def string_to_binary(str)
    str.bytes.map{|d| d.to_s(2)}.map{|b| b.rjust(8, '0')}.join
end

#for getting specific values to tamper the ciphertext with to control 
#the padding bytes of the corresponding plain text
def get_tampered_values(padding_byte_val, known_indices, known_values)
    tampered_values = []

    for i in 0..(known_indices.length()-1) do
        value_to_xor = known_values[i]
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

# puts string_to_binary(encrypted[30]).to_i(2)

binary_cipher_text = string_to_binary(encrypted)


tamper_ciphertext(binary_cipher_text, int_to_binary(15), 1)




#fill in what we know about I3
known_indices = [31]
known_values = [220]

#calculate necessary tampered values, the first 
#argument specificies the desired value in the 
#plaintext block
tampered_values = get_tampered_values(2, known_indices, known_values)

# put tampered_values in
for i in 0..(known_values.length()-1) do
    tamper_ciphertext(binary_cipher_text, tampered_values[i], known_indices[i])
end

#receive user input for brute force
byte_to_edit = 30
new_byte_val = int_to_binary(ARGV[0].to_i)
# new_byte_val = int_to_binary(216)
tamper_ciphertext(binary_cipher_text, new_byte_val, byte_to_edit)


#reconstruct the tampered ciphertext to a format that can be passed to the decryption algorithm
reconstructed_string_ciphertext = binary_cipher_text.scan(/.{8}/).map{|m| m.to_i(2)}.map{|n| n.chr}.join



#perform the decryption
decipher = OpenSSL::Cipher::AES.new(128, :CBC)
decipher.decrypt
decipher.key = key
decipher.iv = iv


#this will throw an error if padding is bad
plain = decipher.update(reconstructed_string_ciphertext) + decipher.final







