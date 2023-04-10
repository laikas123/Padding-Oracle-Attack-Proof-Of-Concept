#!/bin/bash
for i in {0..255}
do
   #only print the number if there is no error from executing
   #the script with the given argument passed
   if ruby ruby_encrypt_decrypt.rb $i 2>/dev/null; then
     echo $i
  fi
done



