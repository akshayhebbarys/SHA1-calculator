#include<stdio.h>
#include<stdlib.h>
#include"sha.h"

#define k1 0x5A827999
#define k2 0x6ED9EBA1
#define k3 0x8F1BBCDC
#define k4 0xCA62C1D6

#define left_rotate(k,bits)\
    ((k<<bits)|(k>>(32-bits)))

void file_read(char *s)
{
    sha message;
    init(&message);
    FILE *fp;
    fp = fopen(s,"rb");
    char c;
    c = getc(fp);
    while(!feof(fp))
    {
        calculate(&message,c);
        c = getc(fp);
    }
    pad_message(&message);
    disp(message);
    fclose(fp);
}

void string_read(char *s)
{
    sha message;
    init(&message);
    int i=0;
    while(s[i]!='\0')
    {
        calculate(&message, s[i]);
        ++i;
    }
    pad_message(&message);
    disp(message);
}


void init(sha *op)
{
    int i;
    op->message_digest[0]=0x67452301;
    op->message_digest[1]=0xEFCDAB89;
    op->message_digest[2]=0x98BADCFE;
    op->message_digest[3]=0x10325476;
    op->message_digest[4]=0xC3D2E1F0;
    op->lower_count = 0;
    op->higher_count = 0;
    op->completed = 0;
    op->count = 0;
    op->sub_count = 0;
    for(i=0;i<16;++i)
        op->message[i] = 0;
}

void calculate(sha *op, unsigned char c)
{
    int i;
    if(op->sub_count == 4)
    {
        ++(op->count);
        op->sub_count = 0;
    }
    op->message[op->count] = ((op->message[op->count])<<8)| c;
    ++(op->sub_count);


    op->lower_count += 8;
    if(op->lower_count==0)
    {
        ++(op->higher_count);
        if(op->higher_count==0)
        {
            printf("\nSize of input file exceeded the limit\n");
            exit(0);
        }
    }

    if((op->count == 15)&&(op->sub_count == 4))
    {
        process_message(op);
        op->count = 0;
        op->sub_count = 0;
        for(i=0;i<16;++i)
            op->message[i] = 0;
    }
}

void disp(sha op)
{
    int i;
    if(op.completed)
    {
        printf("\n\nSHA-1 : ");
        for(i=0;i<5;++i)
            printf("%X ",op.message_digest[i]);
        printf("\n\n");
    }
    else
        printf("\nSHA-1 is not calculated\n");
}

void process_message(sha *op)
{
    int i;
    unsigned word[80], a[5], temp;
    for(i=0;i<16;++i)
        word[i] = op->message[i];
    for(i=16;i<80;++i)
        word[i] = left_rotate(((word[i-3]) ^ (word[i-8]) ^ (word[i-14]) ^ (word[i-16])) , 1);

    for(i=0;i<5;++i)
        a[i] = op->message_digest[i];

    for(i=0;i<20;++i)
    {
        temp =0;
        temp = left_rotate(a[0],5) + ((a[1]&a[2]) | ((~a[1])&a[3])) + a[4] + word[i] + k1;
        a[4] = a[3]; a[3] = a[2]; a[2] = left_rotate(a[1],30); a[1] = a[0]; a[0] = temp;
    }

    for(i=20;i<40;++i)
    {
        temp=0;
        temp = left_rotate(a[0], 5) + ((a[1])^(a[2])^(a[3])) + a[4] + word[i] + k2;
        a[4] = a[3]; a[3] = a[2]; a[2] = left_rotate(a[1],30); a[1] = a[0]; a[0] = temp;
    }

    for(i=40;i<60;++i)
    {
        temp=0;
        temp = left_rotate(a[0], 5) + ((a[1]&a[2])|(a[1]&a[3])|(a[2]&a[3])) + a[4] + word[i] + k3;
        a[4] = a[3]; a[3] = a[2]; a[2] = left_rotate(a[1],30); a[1] = a[0]; a[0] = temp;
    }

    for(i=60;i<80;++i)
    {
        temp=0;
        temp = left_rotate(a[0], 5) + ((a[1])^(a[2])^(a[3])) + a[4] + word[i] + k4;
        a[4] = a[3]; a[3] = a[2]; a[2] = left_rotate(a[1],30); a[1] = a[0]; a[0] = temp;
    }

    for(i=0;i<5;++i)
        op->message_digest[i] += a[i];
}

void pad_message(sha *op)
{
    int i;
    if(op->sub_count == 4)
    {
        ++(op->count);
        op->message[op->count] = 0x80000000;
    }
    else

    if(op->sub_count == 0)
        op->message[op->count] = 0x80000000;

    else
    {
        op->message[op->count] = ((op->message[op->count])<<8) | 0x80 ;
        ++(op->sub_count);
        while(op->sub_count!=4)
        {
            op->message[op->count] = ((op->message[op->count])<<8);
            ++(op->sub_count);
        }
    }


    if(op->count >13)
    {
        while(!((op->count == 15)&&(op->sub_count == 4)))
        {
            if((op->sub_count == 4)&&(op->count<15))
            {
                op->message[++(op->count)] = 0;
            }
            else
            {
                op->message[op->count] = (op->message[op->count]) << 8;
                ++(op->sub_count);
            }
        }
        process_message(op);

        for(i=0;i<16;++i)
            op->message[i] = 0;
    }

    op->message[14] = op->higher_count;
    op->message[15] = op->lower_count;

    process_message(op);
    op->completed = 1;
}

/*
unsigned left_rotate(unsigned k, int bits)
{
    k = (k<<bits)|(k>>(32-bits));
    return k;
}
*/
