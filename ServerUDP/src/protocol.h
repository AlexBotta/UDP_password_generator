#ifndef PASSWORD_PROTOCOL_H
#define PASSWORD_PROTOCOL_H

#define SERVER_ADDRESS "127.0.0.1" // Replace with "passwdgen.uniba.it" in deployment
#define SERVER_PORT 8888

#define MAX_PASSWORD_LENGTH 32
#define MIN_PASSWORD_LENGTH 6

#define BUFFER_SIZE 128

// Command Identifiers
#define CMD_NUMERIC 'n'
#define CMD_ALPHA 'a'
#define CMD_MIXED 'm'
#define CMD_SECURE 's'
#define CMD_UNAMBIGUOUS 'u'
#define CMD_HELP 'h'
#define CMD_QUIT 'q'

// Ambiguous Characters
#define AMBIGUOUS_CHARS "0Oo1lIi2Zz5Ss8B"

// Function prototypes for password generation
void generate_numeric(char *buffer, int length);
void generate_alpha(char *buffer, int length);
void generate_mixed(char *buffer, int length);
void generate_secure(char *buffer, int length);
void generate_unambiguous(char *buffer, int length);

#endif
