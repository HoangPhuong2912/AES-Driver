#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/uaccess.h>
#include <crypto/skcipher.h>
#include "aes.h"

#define DEVICE_NAME "aes"
#define AES_BLOCK_SIZE 16

static int major = 0;
static char *secretKey;
static char *_16_bytes_key = "14abmdwblzl6c9hx";
static char *_24_bytes_key = "wvfhkkyq9nuhgsbf85iribm4";
static char *_32_bytes_key = "rsua015kdzq3tiypc3j74j3d6z50j7g6";
static unsigned short use_key = 0;

module_param(major, int, 0600);
module_param(use_key, ushort, 0600);

static void print_hex_dump1(const char *label, const u8 *data, size_t len) {
    char buffer[2 * len + 1];
    size_t i;
    for (i = 0; i < len; ++i) {
        sprintf(buffer + 2 * i, "%02x", data[i]);
    }
    buffer[2 * len] = '\0';
    pr_info("%s: %s\n", label, buffer);
}

static uint8_t nr_of_pads(char *buffer, int size) {
    unsigned char c = buffer[size - 1];
    if (c > 15) {
        return 0;
    }
    return (uint8_t)c;
}

static void apply_padding(u8 *buffer, int buffer_size, int data_size) {
    int padding_size = buffer_size - data_size;
    memset(buffer + data_size, padding_size, padding_size);
}

static char *aes_decrypt(char *data, unsigned int size, unsigned long *actualSize) {
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg;
    int ret;
    char *buffer;

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Failed to allocate transform for AES\n");
        return NULL;
    }
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_err("Failed to allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }
    ret = crypto_skcipher_setkey(tfm, secretKey, strlen(secretKey));
    if (ret) {
        pr_err("Failed to set key\n");
        goto out_free_req;
    }

    buffer = kmalloc(size, GFP_KERNEL);
    if (!buffer) {
        pr_err("Failed to allocate buffer\n");
        ret = -ENOMEM;
        goto out_free_req;
    }
    memcpy(buffer, data, size);
    sg_init_one(&sg, buffer, size);
    skcipher_request_set_crypt(req, &sg, &sg, size, NULL);
    ret = crypto_skcipher_decrypt(req);
    if (ret) {
        pr_err("Decryption failed\n");
        kfree(buffer);
        goto out_free_req;
    }

    *actualSize = size - nr_of_pads(buffer, size);
    print_hex_dump1("Decrypted", buffer, *actualSize);

    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
    return buffer;

out_free_req:
    skcipher_request_free(req);
out:
    crypto_free_skcipher(tfm);
    return NULL;
}

static char *aes_encrypt(char *data, size_t size) {
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg;
    int ret, padded_size;
    char *buffer;

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Failed to allocate transform for AES\n");
        return NULL;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_err("Failed to allocate skcipher request\n");
        goto out;
    }

    ret = crypto_skcipher_setkey(tfm, secretKey, strlen(secretKey));
    if (ret) {
        pr_err("Failed to set key\n");
        goto out_free_req;
    }

    padded_size = (size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
    buffer = kmalloc(padded_size, GFP_KERNEL);
    if (!buffer) {
        pr_err("Failed to allocate buffer\n");
        goto out_free_req;
    }
    memcpy(buffer, data, size);
    apply_padding(buffer, padded_size, size);

    sg_init_one(&sg, buffer, padded_size);
    skcipher_request_set_crypt(req, &sg, &sg, padded_size, NULL);

    ret = crypto_skcipher_encrypt(req);
    if (ret) {
        pr_err("Encryption failed\n");
        kfree(buffer);
        goto out_free_req;
    }

    print_hex_dump1("Encrypted", buffer, padded_size);

    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
    return buffer;

out_free_req:
    skcipher_request_free(req);
out:
    crypto_free_skcipher(tfm);
    return NULL;
}

static int misc_dev_open(struct inode *inode, struct file *file) {
    return 0;
}

static int misc_dev_release(struct inode *inode, struct file *file) {
    return 0;
}

static long misc_ioctl(struct file *filp, unsigned int cmd, unsigned long data) {
    long retval = 0;
    struct user_data user_data;
    char *buffer = NULL, *buffer2 = NULL, *buffer3 = NULL;
    unsigned long actualSize;

    if (copy_from_user(&user_data, (struct user_data __user *)data, sizeof(struct user_data))) {
        return -EFAULT;
    }

    switch (cmd) {
        case AES_ENCRYPT: {
            buffer = kzalloc(user_data.file_size, GFP_KERNEL);
            if (!buffer) {
                pr_err("Memory insufficient\n");
                retval = -ENOMEM;
                break;
            }
            if (copy_from_user(buffer, user_data.file_content, user_data.file_size)) {
                retval = -EFAULT;
                goto error;
            }
            buffer2 = aes_encrypt(buffer, user_data.file_size);
            if (!buffer2) {
                pr_err("Encryption failed\n");
                retval = -1;
                goto error;
            }
            if (copy_to_user(user_data.encrypted_file_content, buffer2, user_data.encrypted_file_size)) {
                retval = -EFAULT;
                goto error2;
            }
            break;
        }
        case AES_DECRYPT: {
            buffer = kzalloc(user_data.encrypted_file_size, GFP_KERNEL);
            if (!buffer) {
                pr_err("Memory insufficient\n");
                retval = -ENOMEM;
                break;
            }
            if (copy_from_user(buffer, user_data.encrypted_file_content, user_data.encrypted_file_size)) {
                retval = -EFAULT;
                goto error;
            }
            buffer2 = aes_decrypt(buffer, user_data.encrypted_file_size, &actualSize);
            if (!buffer2) {
                retval = -1;
                goto error;
            }
            buffer3 = kzalloc(actualSize + 1, GFP_KERNEL);
            if (!buffer3) {
                retval = -ENOMEM;
                goto error2;
            }
            strncpy(buffer3, buffer2, actualSize);
            buffer3[actualSize] = '\0';
            if (copy_to_user(user_data.file_content, buffer3, actualSize)) {
                retval = -EFAULT;
                goto error3;
            }
            break;
        }
        default: {
            pr_info("No such option\n");
            retval = -EINVAL;
            break;
        }
    }

    kfree(buffer3);
error3:
    kfree(buffer2);
error2:
    kfree(buffer);
error:
    return retval;
}

static const struct file_operations my_device_fops = {
    .owner = THIS_MODULE,
    .open = misc_dev_open,
    .release = misc_dev_release,
    .unlocked_ioctl = misc_ioctl
};

static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &my_device_fops,
};

static int __init aes_init(void) {
    int retval;

    retval = misc_register(&misc_dev);
    if (retval) {
        pr_err("Register misc device failed\n");
        return retval;
    }

    switch (use_key) {
        case 0:
            secretKey = _16_bytes_key;
            break;
        case 1:
            secretKey = _24_bytes_key;
            break;
        case 2:
            secretKey = _32_bytes_key;
            break;
        default:
            retval = -EINVAL;
            misc_deregister(&misc_dev);
            return retval;
    }

    pr_info("Registered device: %s\n", DEVICE_NAME);
    return retval;
}

static void __exit aes_exit(void) {
    misc_deregister(&misc_dev);
    if (secretKey) {
        memset(secretKey, 0, strlen(secretKey));
    }
}

module_init(aes_init);
module_exit(aes_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Me");

