# PAM Authentication Module for QMK Keyboard

Note: I used AI to help with some of the code and documentation

This module enables authentication through a QMK keyboard using a hardware challenge-response mechanism.

So any time you're asked to authenticate locally (eg unlock your screen, login, sudo, etc) the computer will send a message to your keyboard and when you press your 'authenticate' key, you'll be authenticated without having to type in a password.

## Why?

Well, I don't want to type my password every time I log in, but I also don't want to have my keyboard literally type out my password. If I did that, there's almost a 100% chance that I press the wrong button and my password gets sent to chat somewhere.

I could have gone a longer route and tried to make my keyboard a full-on FIDO device (might still do that) but I thought this was a good compromise. I press a button, some info travels along the wire to the computer, and I'm logged in.

On a security scale of 1 to 10 it's maybe a 2 or 3 at best and does mean if someone has access to your keyboard they can authenticate as you with a single button, so there's that. But, again, it's a few shades better than typing out a password macro.

## Requirements
- QMK keyboard with custom firmware supporting raw HID communication.
- `hidapi` library installed on the system.
- PAM-enabled system.

## On the QMK Side

You need QMK code to match, here's an example

```c
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
```

Then, somewhere else:
```c
    case KEYBOARD_SEND_AUTH:
      if (record->event.pressed) {
            send_auth_response(); 
            return false;
        }
    break;
```

Assuming you define `KEYBOARD_SEND_AUTH` as a custom keycode somewhere.

Finally, have a `secrets.h` file in the same place as your keymap, it should contain your key, something like this:
```c
#ifndef SECRETS_H
#define SECRETS_H

static const uint8_t AUTH_KEY[] = {0x10, 0x10, 0xde, 0xad}; 

#endif

```

Finally-Finally, be sure your rules.mk has this:
```c
RAW_ENABLE = yes
```

## Installation Instructions

### Check your hardware address

1. Find your keyboard's vendor id and product id by running `lsusb` and finding some numbers XXXX:XXXX for your keyboard. The first 4 are your vendor ID and the second are the device id.

2. Replace the values of vendor id and product id in the C code

### Setting Up the Key
1. Create a directory for the authentication key:
```bash
   sudo mkdir -p /etc/pam_keyboard_auth
```

2. Create an authentication key:

```bash
echo -ne "\x10\x10\xde\xad" | sudo tee /etc/pam_keyboard_auth/auth.key
```
(Replace \x10\x10\xde\xad with whatever 4-byte key you want, just make sure it's the same as in the QMK file)

3. Secure the key file:

```bash
sudo chmod 600 /etc/pam_keyboard_auth/auth.key
sudo chmod 700 /etc/pam_keyboard_auth
```

4. Building the PAM Module
Compile the module:
```bash
gcc -fPIC -shared -o pam_keyboard_auth.so pam_keyboard_auth.c -lpam -lhidapi-hidraw
```

5. Move the module to the PAM security directory:
```bash
sudo mv pam_keyboard_auth.so /lib/x86_64-linux-gnu/security
```

6. Configuring PAM
Edit your PAM configuration, e.g., /etc/pam.d/common-auth:

```bash
sudo vim /etc/pam.d/common-auth
```

Add the following line:

```plaintext
auth sufficient pam_keyboard_auth.so
```
(Ensure this line is above other auth lines for this module to take precedence.)

## How It Works
We're kind of doing cryptography in a super simple way. The computer has a simple private key installed and the keyboard has the same private key installed. Rather than asking the keyboard for the key directly, it's XORd with a random integer array and the keyboard has to respond with the value XORd back with the actual key.

This basically means that you're not sending your actual key at any point. But it's not super hard to work out if you were sniffing data. 

The PAM module verifies the response against the expected value to grant or deny access.

## Usage
After setup, the authentication mechanism will trigger automatically when PAM requests authentication (e.g., during login or sudo).
Ensure your QMK keyboard is connected and running the required firmware.
