#ifndef _AES_H_
#define _AES_H_

#define IOCTL_MAGIC_NUMBER 'k'
#define AES_BLOCK_SIZE 16
#define DEVICE_NAME "aes"

struct user_data{
	char *file_content;
	unsigned int file_size;
	char *encrypted_file_content;
	unsigned int encrypted_file_size;
};

#define AES_ENCRYPT _IOWR(IOCTL_MAGIC_NUMBER,0,struct user_data)
#define AES_DECRYPT _IOWR(IOCTL_MAGIC_NUMBER,1,struct user_data)
#endif
