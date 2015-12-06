// Only modify this file to include
// - function definitions (prototypes)
// - include files
// - extern variable definitions
// In the appropriate section

#ifndef _Teensy_U2F_H_
#define _Teensy_U2F_H_
#include "Arduino.h"
//add your includes for the project Teensy_U2F here

#include <Entropy.h>
#include <EEPROM.h>
#include "mbedtls/sha256.h"

#define DEBUG 1
#define USE_MBDEDTLS_ECC 1

// Whether to use ECC from mbdedTLS implementation or micokay ECC
#ifdef USE_MBDEDTLS_ECC
#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/bignum.h"
#else
#include <uECC.h>
#endif

//end of add your includes here

#define TYPE_INIT               0x80  // Initial frame identifier


#define U2FHID_PING         (TYPE_INIT | 0x01)  // Echo data through local processor only
#define U2FHID_MSG          (TYPE_INIT | 0x03)  // Send U2F message frame
#define U2FHID_LOCK         (TYPE_INIT | 0x04)  // Send lock channel command
#define U2FHID_INIT         (TYPE_INIT | 0x06)  // Channel initialization
#define U2FHID_WINK         (TYPE_INIT | 0x08)  // Send device identification wink
#define U2FHID_ERROR        (TYPE_INIT | 0x3f)  // Error response

#define CID_BROADCAST           0xffffffff  // Broadcast channel id

#define U2FHID_IF_VERSION       2  // Current interface implementation version
#define CAPFLAG_WINK            0x01	// Device supports WINK command
#define CAPFLAG_LOCK            0x02	// Device supports LOCK command

#define U2F_REGISTER        0x01
#define U2F_AUTHENTICATE    0x02
#define U2F_VERSION         0x03

// Low-level error codes. Return as negatives.
#define ERR_NONE 0x00 // No error
#define ERR_INVALID_CMD 0x01 // Invalid command
#define ERR_INVALID_PAR 0x02 // Invalid parameter
#define ERR_INVALID_LEN 0x03 // Invalid message length
#define ERR_INVALID_SEQ 0x04 // Invalid message sequencing
#define ERR_MSG_TIMEOUT 0x05 // Message has timed out
#define ERR_CHANNEL_BUSY 0x06 // Channel busy
#define ERR_LOCK_REQUIRED 0x0a // Command requires channel lock
#define ERR_INVALID_CID 0x0b // Invalid CID
#define ERR_OTHER 0x7f // Other unspecified error


#define MAX_INITIAL_PACKET 57
#define MAX_CONTINUATION_PACKET 59

#define STATE_CHANNEL_AVAILABLE 0
#define STATE_CHANNEL_WAIT_CONT 1

#define SW_NO_ERROR                       0x9000
#define SW_CONDITIONS_NOT_SATISFIED       0x6985
#define SW_WRONG_DATA                     0x6A80
#define SW_WRONG_LENGTH                   0x6700
#define SW_INS_NOT_SUPPORTED              0x6D00
#define SW_CLA_NOT_SUPPORTED              0x6E00


//add your function definitions for the project Teensy_U2F here

void processMessage();
void doHIDOutput();
void doHIDErrorOutput(uint8_t err);
void u2f_register(byte data[], uint32_t dataLen);
void u2f_version(byte data[], uint32_t dataLen);
void u2f_authenticate(byte P1, byte data[], uint32_t dataLen);




//Do not add code below this line
#endif /* _Teensy_U2F_H_ */
