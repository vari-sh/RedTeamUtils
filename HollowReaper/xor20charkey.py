'''

    Author: vari.sh

    Description: This program XOR the shellcode
    
'''


#!/usr/bin/env python3
def xor_bytes(shellcode, key_bytes):
    """
    Applies the XOR operation to each byte of the shellcode using the key.
    The key is repeated if the shellcode is longer.
    """
    result = []
    key_length = len(key_bytes)
    for i, b in enumerate(shellcode):
        result.append(b ^ key_bytes[i % key_length])
    return result

def main():
    # Shellcode in the form of a list of bytes (decimal or hexadecimal)
    shellcode = [0xe8, 0xc0, 0x4d]

    # Define the key as a 20-character string.
    # For example: "0123456789abcdefghij"
    key_str = "0123456789abcdefghij"
    if len(key_str) != 20:
        print("The key must be 20 characters long!")
        return

    # Convert the key into a list of numerical values (bytes)
    key_bytes = [ord(c) for c in key_str]

    # Apply XOR to the shellcode
    xor_result = xor_bytes(shellcode, key_bytes)

    # Format the result in the same format: 0xXX, 0xXX, ...
    formatted_result = ", ".join("0x{:02X}".format(b) for b in xor_result)
    print("XORed Shellcode:")
    print(formatted_result)

if __name__ == "__main__":
    main()
