#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <hidapi/hidapi.h>
#include <errno.h>
#include <sys/stat.h>

#define VENDOR_ID  0x0000
#define PRODUCT_ID 0x0000
#define READ_TIMEOUT_MS 5000

#define SECURITY_CHALLENGE_SIZE 32
#define PACKET_SIZE 64
#define CMD_CHALLENGE  0x02
#define CMD_RESPONSE   0x03
#define KEY_SIZE 4  // Size of our key in bytes
#define KEY_FILE "/etc/pam_keyboard_auth/auth.key"

// Match these with QMK's config.h
#define RAW_USAGE_PAGE 0xFF60
#define RAW_USAGE_ID 0x61

static int read_auth_key(unsigned char *key) {
    FILE *key_file;
    struct stat st;
    
    // Check file permissions
    if (stat(KEY_FILE, &st) != 0) {
        syslog(LOG_ERR, "Could not stat key file: %s", strerror(errno));
        return -1;
    }
    
    // Verify file permissions (readable only by root)
    if ((st.st_mode & 077) != 0) {
        syslog(LOG_ERR, "Key file has unsafe permissions");
        return -1;
    }
    
    key_file = fopen(KEY_FILE, "rb");
    if (!key_file) {
        syslog(LOG_ERR, "Could not open key file: %s", strerror(errno));
        return -1;
    }
    
    size_t bytes_read = fread(key, 1, KEY_SIZE, key_file);
    fclose(key_file);
    
    if (bytes_read != KEY_SIZE) {
        syslog(LOG_ERR, "Invalid key file size");
        return -1;
    }
    
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    hid_device *device = NULL;
    unsigned char challenge[SECURITY_CHALLENGE_SIZE];
    unsigned char buffer[PACKET_SIZE] = {0};
    unsigned char auth_key[KEY_SIZE];
    int result = PAM_AUTH_ERR;
    
    openlog("pam_keyboard_auth", LOG_PID, LOG_AUTH);
    
    // Read the authentication key
    if (read_auth_key(auth_key) != 0) {
        goto cleanup;
    }
    
    // Initialize HID API
    if (hid_init()) {
        syslog(LOG_ERR, "Failed to initialize HIDAPI");
        goto cleanup;
    }
    
    // Find the correct HID interface
    struct hid_device_info *devs = hid_enumerate(VENDOR_ID, PRODUCT_ID);
    for (struct hid_device_info *cur_dev = devs; cur_dev; cur_dev = cur_dev->next) {
        if (cur_dev->usage_page == RAW_USAGE_PAGE && cur_dev->usage == RAW_USAGE_ID) {
            device = hid_open_path(cur_dev->path);
            if (device) {
                syslog(LOG_DEBUG, "Successfully opened HID device");
                break;
            }
        }
    }
    hid_free_enumeration(devs);
    
    if (!device) {
        syslog(LOG_ERR, "Failed to find matching HID interface");
        goto cleanup;
    }
    
    // Generate challenge
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        syslog(LOG_ERR, "Failed to open /dev/urandom");
        goto cleanup;
    }
    if (fread(challenge, 1, SECURITY_CHALLENGE_SIZE, urandom) != SECURITY_CHALLENGE_SIZE) {
        syslog(LOG_ERR, "Failed to read challenge from /dev/urandom");
        fclose(urandom);
        goto cleanup;
    }
    fclose(urandom);
    
    // Prepare and send challenge
    buffer[0] = CMD_CHALLENGE;
    memcpy(&buffer[1], challenge, SECURITY_CHALLENGE_SIZE);
    
    if (hid_write(device, buffer, PACKET_SIZE) == -1) {
        syslog(LOG_ERR, "Failed to send challenge: %ls", hid_error(device));
        goto cleanup;
    }
    syslog(LOG_DEBUG, "Sent challenge");
    
    // Wait for response
    memset(buffer, 0, PACKET_SIZE);
    int bytes_read = hid_read_timeout(device, buffer, PACKET_SIZE, READ_TIMEOUT_MS);
    if (bytes_read <= 0) {
        syslog(LOG_ERR, "Timeout or error waiting for response: %d", bytes_read);
        goto cleanup;
    }
    
    if (buffer[0] != CMD_RESPONSE) {
        syslog(LOG_ERR, "Received unexpected command: %d", buffer[0]);
        goto cleanup;
    }
    
    // Verify response (SECURITY_CHALLENGE_SIZE - 1 bytes to match keyboard implementation)
    unsigned char expected[SECURITY_CHALLENGE_SIZE - 1];
    for(int i = 0; i < SECURITY_CHALLENGE_SIZE - 1; i++) {
        expected[i] = challenge[i] ^ auth_key[i % KEY_SIZE];
    }
    
    if (memcmp(expected, &buffer[1], SECURITY_CHALLENGE_SIZE - 1) == 0) {
        syslog(LOG_INFO, "Authentication successful");
        result = PAM_SUCCESS;
    } else {
        syslog(LOG_ERR, "Authentication failed - response verification failed");
    }
    
cleanup:
    if (device) hid_close(device);
    hid_exit();
    closelog();
    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
