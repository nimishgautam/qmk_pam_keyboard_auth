#include "raw_hid.h"
#include "secrets.h"

#define SECURITY_CHALLENGE_SIZE 32
#define SECURITY_RESPONSE_SIZE 32
#define CMD_AUTH_START 0x01
#define CMD_CHALLENGE  0x02
#define CMD_RESPONSE   0x03

uint8_t last_challenge[SECURITY_CHALLENGE_SIZE];
bool challenge_received = false;

void raw_hid_receive(uint8_t *data, uint8_t length) {
    if (data[0] == CMD_CHALLENGE) {
        // Store the challenge
        memcpy(last_challenge, &data[1], SECURITY_CHALLENGE_SIZE);
        challenge_received = true;
        // Don't generate response yet - wait for button press
    }
}

void send_auth_response(void) {
    if (!challenge_received) {
        // First, request a challenge
        uint8_t start[32] = {CMD_AUTH_START};
        raw_hid_send(start, sizeof(start));
        // Wait a bit for the challenge to arrive
        wait_ms(100);
    }
    
    if (challenge_received) {
        // Generate and send response
        uint8_t response[32] = {CMD_RESPONSE};
        for(int i = 0; i < (SECURITY_CHALLENGE_SIZE - 1); i++) {
            response[i + 1] = last_challenge[i] ^ AUTH_KEY[i % sizeof(AUTH_KEY)];
        }
        raw_hid_send(response, sizeof(response));
        // Reset for next auth attempt
        challenge_received = false;
    }
}

enum custom_key_codes {
	// the below key code is filler, but it's good practice to start with SAFE_RANGE as your first key code
	// so you don't accidentally use one of the pre-built ones
	SOME_KEY_CODE = SAFE_RANGE,
	// you can call the key to do the auth whatever, but it will have to match your key handler later
	KEYBOARD_SEND_AUTH,
}

// your custom keycodes here
bool process_record_user(uint16_t keycode, keyrecord_t *record) {

  switch (keycode) {
    case KEYBOARD_SEND_AUTH:
      if (record->event.pressed) {
	// this is where the thing is actually sent
            send_auth_response(); 
        return false;
        }
    break;
  }

  return true;
}
