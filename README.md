# teensy_u2f

## Overview
This is a U2F implementation on Teensy 3.x.  Note there is another similar U2F implemtation [https://github.com/yohanes/teensy-u2f] but this implementation is different in many ways.

U2F stands for "Universal 2nd Factor", it is an open standard for 2nd factor authentication, i.e. users need to login with password + usdb dongle.   See [https://fidoalliance.org/specifications/overview/]

Teensy 3.x is a low cost microcontroller based on 32 bit ARM Cortex M4 , and it compatible with Arduino IDE and libraries. See [https://www.pjrc.com/teensy/index.html]

## Operation
Whenever an end user registers this U2F device on a website, this device will 

1. Generate a keypair
2. Assign a keyhandle - this is just a number from 0-9, as this device will only store 10 keys.
3. Store the private key in the Teensy's EEPROM along with a keyhandle and a 32 bit application identitfier passed by the website
4. (Optional) - Double blink the attached LED bar to indicate to the end user, that a key is being generated, and wait for user to press the button.  Note - the LED bar has 10 LEDs, and led corresponding to the keyhandle will blink.
5. Sign the public key with an attestation private key
6. Return the signed public key to the website.  

The website will remember the key handle and public key along with the end user's profile.


Later on when the website wants to authenticate the end user, the website will ask the device to sign with is private key and pass in the keyhandle and application identifier. Then the device will

1. Check that the passed in keyhandled and 32 bit application identified exists in the EEPROM, fetch the private key from the EEPROM
2. (Optional) - Single blink the appropriate LED, and wait for user to press the button.
3. Sign the challenge param with the private key.
4. Return the signed challenge to the website.

The website will then verify the signed challenge with the previously stored public key. 



## Security
* *Secure Storage* : There is no security element / secure EEPROM in Teensy, and it pretty easy to get the keys out of the device. But this can only happen when you lose the device itself and the attacker gets hold of the device. The keys generated by the device are pretty secure , so attackers hacking the website cannot get to your keys.  

* *Entropy* : For generating high quality keys, this device uses the Teensy Entropy library to seed a HMAC Determninistic random number generator. The Entropy library uses jitter on the watchdog reset interrupt vector to get true random numbers. [https://sites.google.com/site/astudyofentropy/project-definition/timer-jitter-entropy-sources/entropy-library]

* *Crypto* : This device uses the MbedTLS crypto library for random number generation (HMAC-DRBG), digesting (SHA256), key generation (for P256 elliptic curves), ECDSA signing etc. [https://tls.mbed.org/]  This library has a config.h  file where you can put in hash defines to pick and choose which parts of the library you would like to link. For the ECC parts of the crypto, there is alternative to use the kmackay ECC library -  [https://github.com/kmackay/micro-ecc] which is smaller in size.  Also this code uses ECDSA deterministic signing which is more secure.


## Building the code
Although you can build this code in Arduino IDE, it is better to build it Arduino-Eclipse - [http://eclipse.baeyens.it/].

### Getting the libraries ###
1. *MbedTLS* : Setup MbedTLS as an Arduino Library as follows
  * Create an MbedTLS folder in your Arduino Libraries, i.e. in "Arduino/hardware/teensy/avr/libraries/MbedTLS".
  * Create another mbdedtls folder inside this, i.e. "Arduino/hardware/teensy/avr/libraries/MbedTLS/mbedtls".
  * Download mbedtls from [https://tls.mbed.org/download], unzip it in a temporary location, and copy all the  files from "<unzipped location>/include/mbedtls" into the above "mbdedtls" folder. Also copy the files from "<unzipped location>/library" into the same mbedtls folder.  
  * Edit the file "config.h" that was copied from "include/mbedtls" to have the content defined in mbded_tls_config.h

2. *Micro-ECC*: (Optional)  Setup MicroECC as an Arduino Library as follows
  * Create a "uECC" folder under Arduino Libaries
  * Download the zip from [https://github.com/kmackay/micro-ecc] and unzip it under the uECC folder, so that uECC.c and uECC.h are directly in the "uECC" folder. Delete the test directory.
