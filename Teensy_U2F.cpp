// Do not remove the include below
#include "Teensy_U2F.h"



#ifdef USE_MBDEDTLS_ECC
mbedtls_hmac_drbg_context hmac_drbg;
mbedtls_ecp_group curve_secp256r1;
#endif

#ifndef USE_MBDEDTLS_ECC
int MyRNG_Function(uint8_t *dest, unsigned size) {

	for(unsigned i = 0; i < size; i++) {
		dest[i] = Entropy.random(0xFF);
	}
#ifdef DEBUG
	Serial.printf("MyRNG_Function with size:%d\n", size);
	for(unsigned int i = 0; i < size; i++) Serial.printf("%02x", dest[i]);
	Serial.printf("\n");
#endif
	return 1;
}
#endif

void printHex(uint8_t *buf, int size) {
	for(int i = 0; i < size; i++) {
		Serial.printf("%02x", buf[i]);
	}
}

// This device will not support multiple channels concurrently.
byte message[8000];  // maximum message size is 7609 - this is both for input and output of message
int expectedMessageSize = 0; // expected message size - used only during input
int messageSize = 0;    // current message size, if current < expected that means we are waiting for more packets
int messageOffset = 0; // current offset of message - used only during output


byte cmd; // current command
uint32_t cid; // current channel id
byte state = STATE_CHANNEL_AVAILABLE; // current channel state;
byte pack_seq = 0; // expecec paccket sequnce number

#define IS_CONTINUATION_PACKET(x) ( (x) < 0x80)

/**
 * String together the incoming 64 byte packets into messages
 */
void processHIDInput() {
	int n = 0;
	// U2F protocol will always send 64 bit packet
	// and RawHID.recv will always return 64
	byte recv_buffer[64];
	n = RawHID.recv(recv_buffer, 0); // 0 timeout = do not wait
	if (n == 0)
		return;

	uint32_t msg_cid = (recv_buffer[0] << 24) | (recv_buffer[1] << 16)  | (recv_buffer[2] << 8)  | recv_buffer[3];
	int len = (recv_buffer[5]) << 8 | recv_buffer[6];
	byte cmd_or_cont = recv_buffer[4]; //cmd or continuation

#ifdef DEBUG
	Serial.printf("\nGot RAW HID cid=%x, cmd=%x\n", msg_cid, cmd_or_cont, (cmd_or_cont > 0x80 ? len : 0));
#endif

	// Is the channel free, then we expect start of new command
	if (state == STATE_CHANNEL_AVAILABLE) {
		// Did we get an unxpected continuation packet - something is wrong
		if (IS_CONTINUATION_PACKET(cmd_or_cont)) {
#ifdef DEBUG
			Serial.printf("WARNING: Got continuation packet when expecting starting packet. Ignoring packet\n");
#endif
			// Ignote this.  The spec says "Spurious continuation packets appearing without a prior initialization packet will be ignored"
			return;
		}
		// This is start of a new message
		// save the a) ChannelID - cid, b) Command - cmd, c) message size
		cid = msg_cid;
		cmd = cmd_or_cont;
		expectedMessageSize = (recv_buffer[5]) << 8 | recv_buffer[6];
		pack_seq = 0;
		if (expectedMessageSize <= MAX_INITIAL_PACKET) { // if the entire message is <= 57 (MAX_INITIAL_PACKET) bytes, it will fit in the first buffer
			memcpy(message, recv_buffer+7, expectedMessageSize);
			messageSize = expectedMessageSize;

#ifdef DEBUG
			Serial.printf("Got full message in first packet size=%d\n", messageSize);
#endif
			// Entire message has been received, go ahead and process it
			processMessage();
			state = STATE_CHANNEL_AVAILABLE;
		}
		else { // message size needs continuation packets, save this buffer and
			memcpy(message, recv_buffer+7, MAX_INITIAL_PACKET);
			messageSize = MAX_INITIAL_PACKET;
			state = STATE_CHANNEL_WAIT_CONT;
#ifdef DEBUG
			Serial.printf("Got partial message in first packet size=%d\n", messageSize);
#endif
		}
	}
	// If the current channel is waiting for a packet
	else if (state == STATE_CHANNEL_WAIT_CONT) {
		if (msg_cid != cid) { // message is for a different channel , ERROR we only support one channel
#ifdef DEBUG
			Serial.printf("Got message for different channel, we support only 1 channel. Expected_cid=%x, Message_cid=%x\n", cid, msg_cid);
#endif
			doHIDErrorOutput(ERR_OTHER);
			return;
		}
		else if (pack_seq != cmd_or_cont) { // expected packet sequence number did not match - ERROR
#ifdef DEBUG
			Serial.printf("Got wrong sequence number. Expected_seq=%d, Message_seq=%d\n", pack_seq, cmd_or_cont);
#endif
			doHIDErrorOutput(ERR_INVALID_SEQ);
			return;
		}


		// Did we get the last packet
		int remaining = expectedMessageSize - messageSize;
		if (remaining <= MAX_CONTINUATION_PACKET) {
			memcpy(message + messageSize, recv_buffer+5, remaining);
			messageSize+= remaining;

#ifdef DEBUG
			Serial.printf("Got final message in packet:%d \n", pack_seq);
#endif
			// Entire message has been received, go ahead and process it
			processMessage();
			state = STATE_CHANNEL_AVAILABLE;
		} else {
			// We didn't get the last packet yet, read this packet and go back to waiting
			memcpy(message + messageSize, recv_buffer+5, MAX_CONTINUATION_PACKET);
			messageSize+= MAX_CONTINUATION_PACKET;
			pack_seq++;
			state = STATE_CHANNEL_WAIT_CONT;
#ifdef DEBUG
			Serial.printf("Got partial message in packet:%d remaining size=%d\n", (pack_seq-1), (expectedMessageSize - messageSize));
#endif
		}
	}
}
void doHIDErrorOutput(uint8_t err) {
	byte resp_buffer[64];

	// output first block
	resp_buffer[0] = (cid >> 24) & 0xff;
	resp_buffer[1] = (cid >> 16) & 0xff;
	resp_buffer[2] = (cid >>  8) & 0xff;
	resp_buffer[3] = cid & 0xff;

	resp_buffer[4] = U2FHID_ERROR;
	resp_buffer[5] = 0;
	resp_buffer[6] = 1;
	resp_buffer[7] = err;
	RawHID.send(resp_buffer, 100);
}

void doHIDOutput() {
#ifdef DEBUG
	Serial.printf("Responding with cid=%x cmd=%x, messageSize=%d\n", cid, cmd, messageSize);
#endif
	byte resp_buffer[64];

	// output first block
	resp_buffer[0] = (cid >> 24) & 0xff;
	resp_buffer[1] = (cid >> 16) & 0xff;
	resp_buffer[2] = (cid >>  8) & 0xff;
	resp_buffer[3] = cid & 0xff;


	resp_buffer[4] = cmd;
	resp_buffer[5] = messageSize >> 8;
	resp_buffer[6] = messageSize & 0xff;

	int n = messageSize > MAX_INITIAL_PACKET ? MAX_INITIAL_PACKET : messageSize;
	memcpy(resp_buffer+7,message, n);
	int offset = n;
#ifdef DEBUG
	for(uint16_t i = 0; i < 7+n; i++) Serial.printf("%02x", resp_buffer[i]);
	Serial.printf("\n");
#endif
	RawHID.send(resp_buffer, 100);

	uint8_t seq = 0;
	while(offset < messageSize) {
		delay(1); // Give a gap between each packet
		resp_buffer[4] = seq;
		n = (messageSize - offset) > MAX_CONTINUATION_PACKET ?  MAX_CONTINUATION_PACKET : (messageSize - offset);
		memcpy(resp_buffer + 5, message + offset, n);
#ifdef DEBUG
		Serial.printf("Responding continuation packet cid=%x cmd=%d seq=%d offset=%d\n", cid, cmd, seq, offset);
		for(uint16_t i = 0; i < 5+n; i++) Serial.printf("%02x", resp_buffer[i]);
		Serial.printf("\n");
#endif
		RawHID.send(resp_buffer, 100);
		seq ++;
		offset += n;
	}

}

void u2f_errorResponse(uint16_t err) {
	cmd = U2FHID_MSG;
	messageSize = 2;
	message[0] = err >> 8;
	message[1] = err & 0xff;
	doHIDOutput();
}


void processMessage() {
	if (cmd == U2FHID_INIT) {
#ifdef DEBUG
		Serial.printf("Got U2FHID_INIT cid=%d\n", cid);
#endif
		uint32_t newCid = cid;
		if (cid == CID_BROADCAST) {
			newCid = Entropy.random() & 0xff;  // Since we support only one channel - just use 1 for the channel id
#ifdef DEBUG
			Serial.printf("Allocating a random cid=%x\n", newCid);
#endif
		}
		// message[0..8] is a 8 byte nonce in the input message which will be passes as is to the output
		// message[8..12] is a 4 byte Channel Identifier, pass it unchanged, unless it is broadcast request
		message[8] = (newCid >> 24) & 0xff;
		message[9] = (newCid >> 16) & 0xff;
		message[10] = (newCid >>  8) & 0xff;
		message[11] = newCid & 0xff;

		message[12] = U2FHID_IF_VERSION;
		message[13] = 1; //major
		message[14] = 0; //minor
		message[15] = 1; //build
		message[16] = CAPFLAG_WINK; // supports the wing capability
		messageSize = 17;

		doHIDOutput();
	}
	else if (cmd == U2FHID_PING) {
#ifdef DEBUG
		Serial.printf("Got U2FHID_PING cid=%x\n", cid);
#endif
		doHIDOutput(); // output everything unchanged
	}
	else if (cmd == U2FHID_WINK) {
#ifdef DEBUG
		Serial.printf("Got U2FHID_WINK cid=%x\n", cid);
#endif
		// blink lights
		doHIDOutput(); // output everything unchanged
	}
	else if (cmd == U2FHID_MSG) {
		byte CLA = message[0];
		byte INS = message[1];
		byte P1 = message[2];
		byte P2 = message[3];
		uint32_t reqlength = (message[4] << 16) | (message[5] << 8) | message[6];

#ifdef DEBUG
		Serial.printf("Got U2FHID_MSG cid=%x, CLA=%d, INS=%x, P1=%d, P2=%d, reqLength=%d\n", cid, CLA, INS, P1, P2, reqlength);
#endif
		if (INS == U2F_REGISTER) {
			u2f_register(message+7, reqlength);
		}
		else if (INS == U2F_AUTHENTICATE) {
			u2f_authenticate(P1, message + 7, reqlength);
		}
		else if (INS == U2F_VERSION) {
			u2f_version(message + 7, reqlength);
		}
		else {
#ifdef DEBUG
			Serial.printf("Got wrong unknown INS:%d cid=%x\n", INS, cid);
#endif
			u2f_errorResponse(SW_INS_NOT_SUPPORTED);
		}

	}
	else {
#ifdef DEBUG
		Serial.printf("Got wrong unknown command:%d cid=%x\n", cmd, cid);
#endif
		doHIDErrorOutput(ERR_INVALID_CMD);

	}
}


/*
Instructions to generate attestation certificate using open ssl
https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations
https://www.guyrutenberg.com/2013/12/28/creating-self-signed-ecdsa-ssl-certificate-using-openssl/

 P-256 (also secp256r1)  EC key pair is    W = dG   (Note secp256k1 is Koblitz curve - not P256)
 d = private key is it 256 bits (32 bytes)
 G = generator point - it is part of the curve definition
 W = public key point - it is a (256, 256) bits  - 64 bytes

1) generate a key pair - the private key will be saved in PKCS8 format in ecprivkey.pem
openssl ecparam -name prime256v1 -genkey -noout -out ecprivkey.pem

2) dump out the private key in hex format - it will be a 32 byte key
 openssl asn1parse  -in ecprivkey.pem

3) compute the public key from the private key and the curve
openssl ec -in ecprivkey.pem -pubout -out ecpubkey.pem

4) dump out the public key in hex format - it will be 66 byte - the first two bytes are 00 04,
  openssl ec -in ecprivkey.pem -pubout -text
  after that is the point W - 32 byte + 32 byte

5) generate a self signed certificate
  openssl req -new -x509 -key ecprivkey.pem -out server.pem -days 3650

For the Certificate name give a unique certificate name. There is a 128 bit unique identification number burned into every
Teensy chip  - see http://cache.freescale.com/files/32bit/doc/data_sheet/K20P64M72SF1.pdf
You can print out the number from your Teensy using this simple program given below



6) Display the certificate
  openssl x509 -in server.pem -text -noout

38510000 7233001B 001D5019 31604E45

-----------------------------------------
// Program to print out unique serial number embedded in Freescale Teensy 3.1 chip
// Taken from https://forum.pjrc.com/archive/index.php/t-25522.html

void setup() {
  char ID[32];
  // The 4 32-bit UID registers are defined in the firmware in kinetis.h,
  sprintf(ID, "%08lX %08lX %08lX %08lX", SIM_UIDH, SIM_UIDMH, SIM_UIDML, SIM_UIDL);

  Serial.begin(115200);
  while (!Serial);
  pinMode(13, OUTPUT);
  digitalWrite(13, HIGH); // just to show that serial port is opened
  delay (1000);
  Serial.print("Reading 128-bit UniqueID from chip: ");
  Serial.println(ID);
}
void loop() {
}

*/

// A self issued attestation certificate generated using OpenSSL commands above
// Subject: C=US, CN=Teensy 38510000 7233001B 001D5019 31604E45
byte attestCert[] = {
  0x30, 0x82, 0x01, 0xcc, 0x30, 0x82, 0x01, 0x71, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x09, 0x00, 0x92, 0x5d, 0xdf, 0xb7, 0x83, 0x7f, 0x84, 0x62,
  0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
  0x30, 0x42, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
  0x02, 0x55, 0x53, 0x31, 0x33, 0x30, 0x31, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x0c, 0x2a, 0x54, 0x65, 0x65, 0x6e, 0x73, 0x79, 0x20, 0x33, 0x38, 0x35,
  0x31, 0x30, 0x30, 0x30, 0x30, 0x20, 0x37, 0x32, 0x33, 0x33, 0x30, 0x30,
  0x31, 0x42, 0x20, 0x30, 0x30, 0x31, 0x44, 0x35, 0x30, 0x31, 0x39, 0x20,
  0x33, 0x31, 0x36, 0x30, 0x34, 0x45, 0x34, 0x35, 0x30, 0x1e, 0x17, 0x0d,
  0x31, 0x35, 0x31, 0x32, 0x30, 0x33, 0x30, 0x38, 0x31, 0x33, 0x30, 0x38,
  0x5a, 0x17, 0x0d, 0x32, 0x35, 0x31, 0x31, 0x33, 0x30, 0x30, 0x38, 0x31,
  0x33, 0x30, 0x38, 0x5a, 0x30, 0x42, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
  0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x33, 0x30, 0x31, 0x06,
  0x03, 0x55, 0x04, 0x03, 0x0c, 0x2a, 0x54, 0x65, 0x65, 0x6e, 0x73, 0x79,
  0x20, 0x33, 0x38, 0x35, 0x31, 0x30, 0x30, 0x30, 0x30, 0x20, 0x37, 0x32,
  0x33, 0x33, 0x30, 0x30, 0x31, 0x42, 0x20, 0x30, 0x30, 0x31, 0x44, 0x35,
  0x30, 0x31, 0x39, 0x20, 0x33, 0x31, 0x36, 0x30, 0x34, 0x45, 0x34, 0x35,
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
  0x42, 0x00, 0x04, 0x1c, 0xbd, 0x93, 0xb6, 0x38, 0x9c, 0x01, 0x88, 0xba,
  0x31, 0x49, 0x44, 0x0e, 0x08, 0x88, 0xad, 0x7b, 0x0a, 0x36, 0xa3, 0x65,
  0x1b, 0x7a, 0x16, 0xfd, 0x77, 0xb7, 0xdf, 0x90, 0x91, 0x0d, 0xb0, 0xcf,
  0x3a, 0x5d, 0x41, 0xa5, 0x94, 0x3d, 0x3b, 0x85, 0xa4, 0xc6, 0x65, 0xa0,
  0x1f, 0x48, 0xf7, 0x0a, 0x21, 0xc4, 0xfb, 0x95, 0x73, 0xf3, 0xd8, 0x75,
  0x1e, 0xf4, 0xfc, 0xc5, 0xf6, 0xa3, 0xf2, 0xa3, 0x50, 0x30, 0x4e, 0x30,
  0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x50, 0x9f,
  0x42, 0x44, 0x21, 0x66, 0x3a, 0xca, 0xd4, 0xc1, 0x8c, 0x31, 0xd1, 0x7a,
  0x7c, 0x35, 0xe8, 0xda, 0x17, 0xb0, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
  0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x50, 0x9f, 0x42, 0x44, 0x21,
  0x66, 0x3a, 0xca, 0xd4, 0xc1, 0x8c, 0x31, 0xd1, 0x7a, 0x7c, 0x35, 0xe8,
  0xda, 0x17, 0xb0, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05,
  0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21,
  0x00, 0xad, 0x27, 0x7f, 0x55, 0x73, 0xc2, 0xc3, 0x30, 0x90, 0xb9, 0x19,
  0x46, 0x05, 0x58, 0xb6, 0xcc, 0x03, 0x87, 0x13, 0x44, 0x68, 0x7c, 0x6e,
  0x83, 0x9e, 0x2d, 0x42, 0xd3, 0xc9, 0x42, 0x41, 0x93, 0x02, 0x21, 0x00,
  0xc5, 0xda, 0x60, 0xea, 0xf2, 0x86, 0xad, 0xb6, 0x9d, 0xa6, 0xca, 0x18,
  0x0e, 0xe2, 0xef, 0x04, 0xd6, 0xfd, 0xbb, 0xa8, 0x8f, 0x9a, 0x7f, 0xfc,
  0x9a, 0x47, 0x66, 0xe6, 0x77, 0xed, 0x97, 0x56
};

byte attestPrivKey[] = {
    0xae, 0x93, 0xa6, 0x20, 0xeb, 0x92, 0x03, 0x69,      0x83, 0x07, 0x92, 0xf3, 0x18, 0x2e, 0x84, 0x87,
	0x1e, 0xbc, 0x32, 0x72, 0x85, 0x0a, 0xa5, 0x3a,      0x6c, 0xde, 0x29, 0x68, 0xca, 0xbb, 0x36, 0x35

};

byte attestPubKey[] = {
   0x04,
   0x1c, 0xbd, 0x93, 0xb6, 0x38, 0x9c, 0x01, 0x88, 0xba, 0x31, 0x49, 0x44, 0x0e, 0x08, 0x88, 0xad,
   0x7b, 0x0a, 0x36, 0xa3, 0x65, 0x1b, 0x7a, 0x16, 0xfd, 0x77, 0xb7, 0xdf, 0x90, 0x91, 0x0d, 0xb0,
   0xcf, 0x3a, 0x5d, 0x41, 0xa5, 0x94, 0x3d, 0x3b, 0x85, 0xa4, 0xc6, 0x65, 0xa0, 0x1f, 0x48, 0xf7,
   0x0a, 0x21, 0xc4, 0xfb, 0x95, 0x73, 0xf3, 0xd8, 0x75, 0x1e, 0xf4, 0xfc, 0xc5, 0xf6, 0xa3, 0xf2
};


/*

-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK6TpiDrkgNpgweS8xguhIcevDJyhQqlOmzeKWjKuzY1oAoGCCqGSM49
AwEHoUQDQgAEHL2TtjicAYi6MUlEDgiIrXsKNqNlG3oW/Xe335CRDbDPOl1BpZQ9
O4WkxmWgH0j3CiHE+5Vz89h1HvT8xfaj8g==
-----END EC PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
MIIBzDCCAXGgAwIBAgIJAJJd37eDf4RiMAoGCCqGSM49BAMCMEIxCzAJBgNVBAYT
AlVTMTMwMQYDVQQDDCpUZWVuc3kgMzg1MTAwMDAgNzIzMzAwMUIgMDAxRDUwMTkg
MzE2MDRFNDUwHhcNMTUxMjAzMDgxMzA4WhcNMjUxMTMwMDgxMzA4WjBCMQswCQYD
VQQGEwJVUzEzMDEGA1UEAwwqVGVlbnN5IDM4NTEwMDAwIDcyMzMwMDFCIDAwMUQ1
MDE5IDMxNjA0RTQ1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHL2TtjicAYi6
MUlEDgiIrXsKNqNlG3oW/Xe335CRDbDPOl1BpZQ9O4WkxmWgH0j3CiHE+5Vz89h1
HvT8xfaj8qNQME4wHQYDVR0OBBYEFFCfQkQhZjrK1MGMMdF6fDXo2hewMB8GA1Ud
IwQYMBaAFFCfQkQhZjrK1MGMMdF6fDXo2hewMAwGA1UdEwQFMAMBAf8wCgYIKoZI
zj0EAwIDSQAwRgIhAK0nf1VzwsMwkLkZRgVYtswDhxNEaHxug54tQtPJQkGTAiEA
xdpg6vKGrbadpsoYDuLvBNb9u6iPmn/8mkdm5nftl1Y=
-----END CERTIFICATE-----


*/


#define EEPROM_KEYOFFSET             4
#define EEPROM_ENTRYSIZE            68
#define EEPROM_ENTRY_APPOFFSET       0
#define EEPROM_ENTRY_KEYOFFSET      32
#define EEPROM_ENTRY_COUNTEROFFSET  64
#define EERPOM_MAXKEYS              10
/*
 microECC library does not produce signature in ASN.1 encoding.
 So we need to convert to an ASN.1 sequence

  ECDSASignature ::= SEQUENCE {
    r   INTEGER,
    s   INTEGER

 */
unsigned int appendSignatureAsDER(uint8_t message[], int &offs, uint8_t signature[64]) {
	int oldOffs = offs;
	message[offs++] = 0x30; // Start of ASN.1 SEQUENCE
	uint8_t *len = message+offs;
	message[offs++] = 68; //total length (32 + 32 + 2 + 2)

	// Loop twice - for R and S
	for(unsigned int i = 0; i < 2; i++) {
		unsigned int sigOffs = i * 32;
		message[offs++] = 0x02;  //header: integer
		message[offs++] = 32;  //32 byte
		if (signature[sigOffs] > 0x7f) { // Integer needs to be represented in 2's completement notion
			message[offs-1] ++;
			message[offs++] = 0; // add leading 0, to indicate it is a positive number
			(*len)++;
		}
		memcpy(message+offs, signature+sigOffs, 32); //R value
		offs +=32;
	}
	return offs - oldOffs;
}

// 55 32 46 5f 56 32    90 00

void u2f_version(byte data[], uint32_t dataLen) {
	if (dataLen != 0) {
#ifdef DEBUG
		Serial.printf("Expecting 0 byte U2F_VERSION message, got: %d\n", dataLen);
#endif
		u2f_errorResponse(SW_WRONG_LENGTH);
		return;
	}
#ifdef DEBUG
	Serial.printf("Got U2F_VERSION message, returning U2F_V2\n");
#endif
	int offs = 0;
	// Returns version string as "U2F_V2"
	// Return SW_NO_ERROR as status
	memcpy(message, "U2F_V2", 6); offs=6;
	message[offs++] =  SW_NO_ERROR >> 8;
	message[offs++] =  SW_NO_ERROR & 0xff;

	messageSize = offs;
	doHIDOutput(); // output the response

}

void u2f_register(byte data[], uint32_t dataLen) {

	// TODO check that dataLen is actually 64
	if (dataLen != 64) {
#ifdef DEBUG
		Serial.printf("Expecting 64 byte U2F_REGISTER message, got: %d\n", dataLen);
#endif
		u2f_errorResponse(SW_WRONG_LENGTH);
		return;
	}

	// Check how many keys we are already storing
	uint8_t numKeys = EEPROM.read(0); // 0's index has number of keys
	if (numKeys > 5) // Temporary code so that EEPROM doesn't get full
		numKeys = 0;
	if (numKeys >= EERPOM_MAXKEYS) {
#ifdef DEBUG
		Serial.printf("EEPROM already has too many keys : %d\n", numKeys);
#endif
		// no more space to register more keys
		u2f_errorResponse(SW_CONDITIONS_NOT_SATISFIED);
		return;
	}
	uint8_t keyHandle = numKeys++;



	// Copy the application param and challenge param out of the request data
	byte applicationParam[32];
	byte challengeParam[32];
	memcpy(challengeParam, data, 32);
	memcpy(applicationParam, data+32, 32);

	// Generate a key pair
	uint8_t pub[65];
	uint8_t priv[32];
	pub[0] = 0x04;
#ifdef USE_MBDEDTLS_ECC

	{
		size_t olen;
		mbedtls_mpi privKey;
		mbedtls_ecp_point publicPoint;

		mbedtls_mpi_init(&privKey);
		mbedtls_ecp_point_init(&publicPoint);

		// Create a Keypair and write it our pub and priv byte arrays
		mbedtls_ecp_gen_keypair(&curve_secp256r1, &privKey, &publicPoint, mbedtls_hmac_drbg_random, &hmac_drbg);
		mbedtls_mpi_write_binary(&privKey, priv, sizeof(priv));
		mbedtls_ecp_point_write_binary(&curve_secp256r1, &publicPoint, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, sizeof(pub));

		mbedtls_mpi_free(&privKey);
		mbedtls_ecp_point_free(&publicPoint);
	}
#else
	uECC_make_key(pub+1, priv, uECC_secp256r1());
#endif

#ifdef DEBUG
	Serial.printf("Generated key:\n");
	Serial.printf("  Priv:");
	for(uint16_t i = 0; i < sizeof(priv); i++) Serial.printf("%02x", priv[i]);
	Serial.printf("\n  Pub:");
	for(uint16_t i = 0; i < sizeof(pub); i++) Serial.printf("%02x", pub[i]);
	Serial.printf("\n  App:");
	for(uint16_t i = 0; i < sizeof(applicationParam); i++) Serial.printf("%02x", applicationParam[i]);
	Serial.printf("\n  Challenge:");
	for(uint16_t i = 0; i < sizeof(challengeParam); i++) Serial.printf("%02x", challengeParam[i]);
	Serial.printf("\n  AttestCert:");
	for(uint16_t i = 0; i < sizeof(attestCert); i++) Serial.printf("%02x", attestCert[i]);
	Serial.printf("\n");
	Serial.printf("  KeyHandle:%d\n", keyHandle);
#endif
	// Create the response message
	int offs = 0;

	// 1st byte is reserver byte 0x05
	message[offs++] = 0x05;

	// Next 65 bytes are public key
	memcpy(message + offs, pub, sizeof(pub)); offs += sizeof(pub);

	// Next is key handle length, which in our case is 1
	message[offs++] = 1;

	// Next is the key handle itself, for us it is index in eprom
	message[offs++] = keyHandle;

	// Next is attestation certificate
	memcpy(message + offs, attestCert, sizeof(attestCert)); offs+= sizeof(attestCert);

	// Finally the signature
	// For the signature we need to calulate the SHA256 digest first
	byte digest[32];
	{
#ifdef DEBUG
		Serial.printf("Calculating digest\n");
#endif
		mbedtls_sha256_context shaContext;

		mbedtls_sha256_init(&shaContext);
		mbedtls_sha256_starts(&shaContext, 0);  // 0=SHA256, 1=SHA224

		byte bt;

		// first byte is reserved byte of 0
		bt = 0;
		mbedtls_sha256_update(&shaContext, (unsigned char*)&bt, 1);

		// Next 32 bytes is application param
		mbedtls_sha256_update(&shaContext, (unsigned char*)applicationParam, sizeof(applicationParam));

		// Next 32 bytes is challenge param
		mbedtls_sha256_update(&shaContext, (unsigned char*)challengeParam, sizeof(challengeParam));


		// Next is keyHandle whose size is keyHandle length
		bt = keyHandle;
		mbedtls_sha256_update(&shaContext, (unsigned char*)&bt, 1);

		// Next 65 bytes is public key
		mbedtls_sha256_update(&shaContext, (unsigned char*)pub, sizeof(pub));

		// finally calculate the digest
		mbedtls_sha256_finish(&shaContext, (unsigned char*)digest);
		mbedtls_sha256_free(&shaContext);

#ifdef DEBUG
		Serial.printf("Digest:");
		for(unsigned int i = 0; i < sizeof(digest); i++) Serial.printf("%02x", digest[i]);
		Serial.printf("\n");
#endif
	}

	// now calculate the ECsignature
	byte signature[64];
#ifdef USE_MBDEDTLS_ECC
	{
		mbedtls_mpi r, s, d;
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);
		mbedtls_mpi_init(&d);
		int ret;
		ret = mbedtls_mpi_read_binary(&d,  attestPrivKey, sizeof(attestPrivKey));
		Serial.printf("read_binary of attestPrivKey returns : %d\n", ret);
		//ret = mbedtls_ecdsa_sign(&curve_secp256r1, &r, &s, &d, digest, sizeof(digest),
		//			mbedtls_hmac_drbg_random, &hmac_drbg);
		ret = mbedtls_ecdsa_sign_det(&curve_secp256r1, &r, &s, &d, digest, sizeof(digest), MBEDTLS_MD_SHA256);

		Serial.printf("ecdsa_sign with attestPrivKey returns : %d\n", ret);
		ret = mbedtls_mpi_write_binary(&r, signature, sizeof(signature)/2);
		Serial.printf("write_binary of r returns : %d, r.size=%d\n", ret, mbedtls_mpi_size(&r));
		ret = mbedtls_mpi_write_binary(&s, signature + sizeof(signature)/2, sizeof(signature)/2);
		Serial.printf("write_binary of s returns : %d, s.size=%d\n", ret, mbedtls_mpi_size(&s));

#ifdef DEBUG
		Serial.printf("Signature:");
		for(unsigned int i = 0; i < sizeof(signature); i++) Serial.printf("%02x", signature[i]);
		Serial.printf("\n");
#endif
		mbedtls_mpi_free(&r);
		mbedtls_mpi_free(&s);
		mbedtls_mpi_free(&d);
	}
#else
	uECC_sign(attestPrivKey, digest, sizeof(digest), signature, uECC_secp256r1());
#endif

	unsigned int siglen = appendSignatureAsDER(message, offs, signature);
#ifdef DEBUG
	Serial.printf("Signature:");
	for(unsigned int i = 0; i < sizeof(signature); i++) Serial.printf("%02x", signature[i]);
	Serial.printf("\n");
	Serial.printf("Signature DER:");
	for(unsigned int i = 0; i < siglen; i++) Serial.printf("%02x", message[offs-siglen+i]);
	Serial.printf("\n");
#endif

	// Set the status as no error
	message[offs++] =  SW_NO_ERROR >> 8;
	message[offs++] =  SW_NO_ERROR & 0xff;

	messageSize = offs;
	doHIDOutput(); // output the response

	// copy the key and applicationParam into EEPROM
	// Each entry in EEPROM is 64 bytes long - 32 bytes for applicationParam, and 32 for private Key
	// The keyHandle is entry number, it starts with 0 and goes on to 9.
	EEPROM.write(0, numKeys);
	for(int i = 0; i < 32; i++) {
		EEPROM.write(EEPROM_KEYOFFSET + (keyHandle * EEPROM_ENTRYSIZE) + EEPROM_ENTRY_APPOFFSET + i,  applicationParam[i]);
	}
	for(int i = 0; i < 32; i++) {
		EEPROM.write(EEPROM_KEYOFFSET + (keyHandle * EEPROM_ENTRYSIZE) + EEPROM_ENTRY_KEYOFFSET + i,  priv[i]);
	}
	for(int i = 0; i < 4; i++) {
		EEPROM.write(EEPROM_KEYOFFSET + (keyHandle * EEPROM_ENTRYSIZE) + EEPROM_ENTRY_COUNTEROFFSET + i,  0);
	}
}

void u2f_authenticate(byte P1, byte data[], uint32_t dataLen) {
	// The data Len is expected to be 66
	if (dataLen != 66) {
#ifdef DEBUG
		Serial.printf("Expecting 66 byte U2F_AUTHENTICATE message, got: %d\n", dataLen);
#endif
		u2f_errorResponse(SW_WRONG_LENGTH);
		return;
	}
	// The key handle length is expected to be 1
	if (data[64] != 1) {
#ifdef DEBUG
		Serial.printf("Invalid KeyHandle length: expecting:1 Got:%d\n", data[64]);
#endif
		u2f_errorResponse(SW_WRONG_DATA);
		return;
	}
	uint8_t keyHandle = data[65];
	if (keyHandle < 0 || keyHandle >= EERPOM_MAXKEYS) {
#ifdef DEBUG
		Serial.printf("Invalid KeyHandle %d, Should be between 0 and %d\n", keyHandle, EERPOM_MAXKEYS);
#endif
		u2f_errorResponse(SW_WRONG_DATA);
		return;
	}

	// Copy the application param and challenge param out of the request data
	byte applicationParam[32];
	byte challengeParam[32];
	memcpy(challengeParam, data, 32);
	memcpy(applicationParam, data+32, 32);


	// Fetch applicationParam from EEPROM
	byte expectedApplicationParam[32];
	for(int i = 0; i < 32; i++) {
		expectedApplicationParam[i] = EEPROM.read(EEPROM_KEYOFFSET + (keyHandle * EEPROM_ENTRYSIZE) + EEPROM_ENTRY_APPOFFSET + i);
	}
	// Check if applicationParam exists in EEPROM
	int matches = 1;
	for(int i = 0; i < 32; i++) {
		if (expectedApplicationParam[i] != applicationParam[i]) matches = 0;
	}


#ifdef DEBUG
	Serial.printf("U2F Authenticate : P1=%02x keyHandle=%d matches=%d\n", P1, keyHandle, matches);
#endif

	if (P1 == 0x07) { // Check-only
		if (!matches) {
#ifdef DEBUG
			Serial.printf("Invalid KeyHandle %d\n", keyHandle);
			Serial.printf("  ApplicationParam:");
			for(int i = 0; i < 32; i++) Serial.printf("%02x", applicationParam[i]);
			Serial.printf("\n  Expected: ApplicationParam:");
			for(int i = 0; i < 32; i++) Serial.printf("%02x", expectedApplicationParam[i]);
			Serial.printf("\n");

#endif
			u2f_errorResponse(SW_WRONG_DATA);
			return;
		} else {
#ifdef DEBUG
			Serial.printf("Keyhandle matched: %d", keyHandle);
#endif
			u2f_errorResponse(SW_CONDITIONS_NOT_SATISFIED);
			return;
		}
	}
	else if (P1 == 0x03) { // enforce-user-presence-and-sign
		// continue below
	}
	else {
#ifdef DEBUG
		Serial.printf("Unknown P1: %02x", P1);
#endif
		u2f_errorResponse(SW_WRONG_DATA);
		return;
	}

	// copy priv key from EEPROM
	uint8_t priv[32];
	for(int i = 0; i < 32; i++) {
		priv[i] = EEPROM.read(EEPROM_KEYOFFSET + (keyHandle * EEPROM_ENTRYSIZE) + EEPROM_ENTRY_KEYOFFSET + i);
	}

	// increment counter
	uint32_t counter;
	EEPROM.get(EEPROM_KEYOFFSET + (keyHandle * EEPROM_ENTRYSIZE) + EEPROM_ENTRY_COUNTEROFFSET, counter);
	counter++;
	EEPROM.put(EEPROM_KEYOFFSET + (keyHandle * EEPROM_ENTRYSIZE) + EEPROM_ENTRY_COUNTEROFFSET, counter);

#ifdef DEBUG
	Serial.printf("Setting counter to %d\n", counter);
#endif
	// Create the response message
	int offs = 0;
	// 1st byte is user presence byte 1
	message[offs++] = 0x01;

	// Next 4 bytes is counter in big endian
	message[offs++] = (counter >> 24) & 0xff;
	message[offs++] = (counter >> 16) & 0xff;
	message[offs++] = (counter >>  8) & 0xff;
	message[offs++] = counter & 0xff;


	// Finally the signature
	// For the signature we need to calulate the SHA256 digest first
	byte digest[32];
	{
#ifdef DEBUG
		Serial.printf("Calculating digest\n");
#endif
		mbedtls_sha256_context shaContext;

		mbedtls_sha256_init(&shaContext);
		mbedtls_sha256_starts(&shaContext, 0);  // 0=SHA256, 1=SHA224

		// First 32 bytes is application param
		mbedtls_sha256_update(&shaContext, (unsigned char*)applicationParam, 32);

		byte bt;

		// Next byte is user presence, it should be 1
		bt = 1;
		mbedtls_sha256_update(&shaContext, (unsigned char*)&bt, 1);

		// Next 4 bytes is counter in big endian
		bt = (counter >> 24) & 0xff;
		mbedtls_sha256_update(&shaContext, (unsigned char*)&bt, 1);
		bt = (counter >> 16) & 0xff;
		mbedtls_sha256_update(&shaContext, (unsigned char*)&bt, 1);
		bt = (counter >>  8) & 0xff;
		mbedtls_sha256_update(&shaContext, (unsigned char*)&bt, 1);
		bt = counter  & 0xff;
		mbedtls_sha256_update(&shaContext, (unsigned char*)&bt, 1);

		// Next 32 bytes is challenge param
		mbedtls_sha256_update(&shaContext, (unsigned char*)challengeParam, 32);

		// finally calculate the digest
		mbedtls_sha256_finish(&shaContext, (unsigned char*)digest);
		mbedtls_sha256_free(&shaContext);
#ifdef DEBUG
		Serial.printf("Digest:");
		for(int i = 0; i < 32; i++) Serial.printf("%02x", digest[i]);
		Serial.printf("\n");
#endif
	}

	// now calculate the ECsignature
	byte signature[64];
#ifdef USE_MBDEDTLS_ECC
	{
		mbedtls_mpi r, s, d;
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);
		mbedtls_mpi_init(&d);
		mbedtls_mpi_read_binary(&d,  priv, sizeof(priv));
		mbedtls_ecdsa_sign(&curve_secp256r1, &r, &s, &d, digest, sizeof(digest),
					mbedtls_hmac_drbg_random, &hmac_drbg);
		mbedtls_mpi_write_binary(&r, signature, sizeof(signature)/2);
		mbedtls_mpi_write_binary(&s, signature + sizeof(signature)/2, sizeof(signature)/2);
		mbedtls_mpi_free(&r);
		mbedtls_mpi_free(&s);
		mbedtls_mpi_free(&d);
	}
#else
	uECC_sign(priv, digest, sizeof(digest), signature, uECC_secp256r1());
#endif

	unsigned int siglen = appendSignatureAsDER(message, offs, signature);
#ifdef DEBUG
	Serial.printf("Signature:");
	for(unsigned int i = 0; i < sizeof(signature); i++) Serial.printf("%02x", signature[i]);
	Serial.printf("\n");
	Serial.printf("Signature DER:");
	for(unsigned int i = 0; i < siglen; i++) Serial.printf("%02x", message[offs-siglen+i]);
	Serial.printf("\n");
#endif

	// Set the status as no error
	message[offs++] =  SW_NO_ERROR >> 8;
	message[offs++] =  SW_NO_ERROR & 0xff;

	messageSize = offs;
#ifdef DEBUG
	Serial.printf("Returning success from u2f_authenticate\n");
#endif
	doHIDOutput(); // output the response

}

// Calback function to pass to mbedtls
int genEntropy(void *obj, unsigned char buf[], size_t buflen) {
	for(unsigned i = 0; i < buflen; i++) {
		buf[i] = Entropy.random(0xFF);
	}
	return 0;

}


//The setup function is called once at startup of the sketch
void setup()
{
#ifdef DEBUG
	 Serial.begin(9600);
#endif

	 // blink 5 times to show that code has started
	 pinMode(13, OUTPUT);
	 for(int i = 0; i < 5; i++) {
		 digitalWrite(13, HIGH); // just to show that serial port is opened
		 delay (300);
		 digitalWrite(13, LOW); // just to show that serial port is opened
		 delay (300);
	 }

#ifdef DEBUG
	 while (!Serial);
	 Serial.printf("\n\n------------------------------------\n");
	 Serial.printf("Starting...\n");
	 Serial.print("Reading 128-bit UniqueID from chip: ");
	 Serial.printf("%08lx %08lx %08lx %08lx\n", SIM_UIDH, SIM_UIDMH, SIM_UIDML, SIM_UIDL);
#endif

	 Entropy.Initialize();


#ifdef USE_MBDEDTLS_ECC
	 // Intialize the Deterministic random number generator
	 mbedtls_hmac_drbg_init(&hmac_drbg);
	 const mbedtls_md_info_t* sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	 mbedtls_hmac_drbg_seed(&hmac_drbg, sha256_info, genEntropy, NULL, NULL, (unsigned int)0);

	 // Intialize the SECP256R1 curve
	 mbedtls_ecp_group_init(&curve_secp256r1);
	 mbedtls_ecp_group_load(&curve_secp256r1, MBEDTLS_ECP_DP_SECP256R1);
#else

	 uECC_set_rng(MyRNG_Function);
#endif

}

uint32_t count = 0;

// The loop function is called in an endless loop
void loop()
{
#ifdef DEBUG
	//if (count%1000 == 0)
	//	Serial.printf("Checking HID input, %d\n", count);
#endif

	count++;
	processHIDInput();
	delay(10);

}

