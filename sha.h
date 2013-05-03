#ifndef SHA_H
#define SHA_H

typedef struct sha
{
    unsigned message_digest[5];
    unsigned lower_count;
    unsigned higher_count;
    int completed;
    unsigned message[16];
    int count;
    int sub_count;
} sha;

void file_read(char *s);
void string_read(char *s);
void init(sha *op);
void calculate(sha *op, unsigned char c);
void disp(sha op);
void pad_message(sha *op);

void process_message(sha *op);
//unsigned left_rotate(unsigned k, int bits);

#endif
