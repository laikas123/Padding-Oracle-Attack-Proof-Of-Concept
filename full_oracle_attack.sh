#!/bin/bash

#since there are 16 bytes per block
#need 16 iterations
START=0
END=15

#remove existing known_values.txt if exists
#to start fresh
rm known_values.txt
touch known_values.txt
for (( c=$START; c<=$END; c++ ))
do
    #first test for possible values
    possible_vals=()
    for i in {0..255}
        do
            if ruby full_oracle_attack.rb $i "query" 2>/dev/null; then
                possible_vals+=($i)
            fi
        done

    certain_values=()

    #check for edge case that padding is different
    #than we assume
    for val in ${possible_vals[@]}; do
        if ruby full_oracle_attack.rb $val "edge" 2>/dev/null; then
            xor=$(( val ^ (c + 1) ))
            certain_values+=($xor)
        fi
    done
    #add the known values to the existig known value
    echo $certain_values >> known_values.txt
done

#print the decrypted result
ruby full_oracle_attack.rb 0 decrypt
