#include<stdio.h>
#include<sys/ioctl.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>
#include"aes.h"
#include<debug.h>
#include<stdlib.h>
#include<stdint.h>
#include<sys/stat.h>
#include<sys/types.h>

#define MAX_INPUT_SIZE 100
#define MAX_FILE_INPUT_SIZE 100000

void print_hex_dump(unsigned char *data,unsigned int size){
    char buf[size * 2 + 1];
    int i;
    for(i = 0; i<size; ++i){
        sprintf(buf + 2*i,"%02x",data[i]);
    }
    buf[size*2] = '\0';
    printf("Encrypted text : %s\n",buf);
}

void enterString(char *str,unsigned int size){
    fgets(str,size,stdin);
    size_t s = strlen(str);
    if(s > 0 && str[s-1] == '\n'){
        str[s-1] = '\0';
    }
}

size_t calculateSize(unsigned int size){
    return ((size + AES_BLOCK_SIZE - 1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE; 
}

struct user_data enc_data,dec_data;

int main(){
    FILE *file = NULL;
    uint8_t fileType;
    int fileDes;
    char c;
    size_t bytesRead, bytesWrite;
    struct stat statbuf;
    char option, *currentDir, *dirName, *fileName, *encFileName, *decFileName, *file_content;
    currentDir = dirName = fileName = encFileName = decFileName = NULL;
    int fd = open("/dev/"DEVICE_NAME, O_RDWR);
    setbuf(stdout, NULL);
    if(fd < 0){
        log_error();
        return -1;
    }

    dirName = malloc(MAX_INPUT_SIZE);
    fileName = malloc(MAX_INPUT_SIZE);
    encFileName = malloc(MAX_INPUT_SIZE);
    decFileName = malloc(MAX_INPUT_SIZE);
    currentDir = malloc(MAX_INPUT_SIZE);
    enc_data.file_content = malloc(MAX_FILE_INPUT_SIZE);
    enc_data.encrypted_file_content = malloc(MAX_FILE_INPUT_SIZE);
    dec_data.file_content = malloc(MAX_FILE_INPUT_SIZE);
    dec_data.encrypted_file_content = malloc(MAX_FILE_INPUT_SIZE);

    if(!currentDir){
        log_error("Khong the cap phat bo nho cho currentDir");
        return -1;
    }

    while(1){
        system("clear");
        printf("========== MENU ==========\n");
        printf("1. Liet ke file\n");
        printf("2. Chuyen thu muc\n");
        printf("3. Tao file\n");
        printf("4. In noi dung file\n");
        printf("5. Viet vao file\n");
        printf("6. Xoa file\n");
        printf("7. Ma hoa file su dung AES\n");
        printf("8. Giai ma file duoc ma hoa bang AES\n");
        printf("9. Ket thuc\n");
        printf("Nhap lua chon : ");
        option = getchar();
        getchar();
        switch(option){
            case '1' : {
                printf("Duong dan hien tai : ");
                system("pwd");
                system("ls -l");
                break;
            }
            case '2' : {
                printf("Nhap duong dan thu muc : ");
                enterString(currentDir,MAX_INPUT_SIZE);
                if(chdir(currentDir)){
                    printf("Duong dan khong hop le\n");
                }
                else
                    printf("Di chuyen den thu muc %s\n",currentDir);
                break;
            }
            case '3' : {
                system("clear");
                printf("1. Thu muc\n");
                printf("2. File\n");
                printf("Nhap lua chon : "); 
                option = getchar();
                getchar();
                switch(option){
                    case '1' : {
                        printf("Nhap ten thu muc : ");
                        enterString(dirName,MAX_INPUT_SIZE);
                        if(mkdir(dirName,0666)){
                            log_error("Khong the tao thu muc");
                        }
                        else
                            printf("Da tao thu muc %s\n",dirName);
                        break;                  
                    }
                    case '2' : {
                        printf("Nhap ten file : ");
                        enterString(fileName,MAX_INPUT_SIZE);
                        file = fopen(fileName,"w");
                        if(!file){
                            log_error("Khong the tao file");
                        }
                        else{
                            printf("Da tao file %s\n",fileName);
                            fclose(file);
                        }
                        break;
                    }
                    default : {
                        printf("Khong co lua chon nay\n");
                        break;
                    }
                }
                break;
            }
            case '4' : {
                printf("Nhap ten file : ");
                enterString(fileName,MAX_INPUT_SIZE);
                file = fopen(fileName,"r");
                if(!file){
                    printf("Khong the mo file\n");
                }
                else{
                    while((c = fgetc(file)) != EOF){
                        putchar(c);
                    }   
                    printf("\n");
                    fclose(file);
                }
                break;
            }
            case '5' : {
                file_content = malloc(MAX_FILE_INPUT_SIZE);
                printf("Nhap ten file : ");
                enterString(fileName,MAX_INPUT_SIZE);
                if(stat(fileName,&statbuf)){
                    printf("File khong ton tai\n");
                    break;
                }
                file = fopen(fileName,"w");
                if(!file){
                    printf("Khong the mo file\n");
                }
                else{
                    printf("Nhap noi dung file : ");
                    enterString(file_content,MAX_FILE_INPUT_SIZE);
                    fwrite(file_content,1,strlen(file_content),file);
                    printf("Ghi thanh cong\n");
                    fclose(file);
                }
                break;
            }
            case '6' : {                
                printf("Nhap ten file : ");
                enterString(fileName,MAX_INPUT_SIZE);
                if(stat(fileName,&statbuf) == 0){
                    if(S_ISREG(statbuf.st_mode)){
                        if(remove(fileName) == 0){
                            printf("Da xoa %s\n",fileName);
                        }
                        else
                            printf("Khong the xoa %s\n",fileName);
                    }
                }
                else{
                    printf("Khong tim thay file\n");
                }
                break;
            }
            case '7' : {
                printf("Nhap ten file : ");
                enterString(fileName,MAX_INPUT_SIZE);
                if(stat(fileName,&statbuf)){
                    printf("File khong ton tai\n");
                    break;
                }
                file = fopen(fileName,"r");
                if(!file){
                    printf("Khong the mo file\n");
                    break;
                }
                bytesRead = fread(enc_data.file_content,1,MAX_INPUT_SIZE,file);
                enc_data.file_size = bytesRead;
                fileDes = open("/dev/"DEVICE_NAME, O_WRONLY);
                if(fileDes < 0){
                    log_error("Khong the mo encryptor");
                    goto f_close;
                }
                fclose(file);
                enc_data.encrypted_file_size = calculateSize(enc_data.file_size);
                
                if(ioctl(fileDes, AES_ENCRYPT, &enc_data)){
                    log_error("Ma hoa that bai ");
                    goto close;
                }

                printf("Nhap ten file ma hoa: ");
                enterString(encFileName, MAX_INPUT_SIZE);
                file = fopen(encFileName, "w");
                if(!file){
                    printf("Khong the mo file ma hoa\n");
                    break;
                }
                bytesWrite = fwrite(enc_data.encrypted_file_content, 1, enc_data.encrypted_file_size, file);
                if(bytesWrite != enc_data.encrypted_file_size){
                    log_error("Loi ghi 1 phan");
                    goto close;
                }
                printf("Ma hoa thanh cong\n");
            close:    
                close(fileDes);
            f_close:
                fclose(file);       
                break;
            }
            case '8' : {        
                printf("Nhap ten file ma hoa: ");
                enterString(encFileName, MAX_INPUT_SIZE);
                if(stat(encFileName,&statbuf)){
                    printf("File khong ton tai\n");
                    break;
                }
                file = fopen(encFileName,"r");
                if(!file){
                    printf("Khong the mo file ma hoa\n");
                    break;
                }
                bytesRead = fread(dec_data.encrypted_file_content,1,MAX_INPUT_SIZE,file);
                dec_data.encrypted_file_size = bytesRead;
                fileDes = open("/dev/"DEVICE_NAME, O_WRONLY);
                if(fileDes < 0){
                    log_error("Khong the mo encryptor");
                    goto f_close1;
                }
                fclose(file);
                    
                if(ioctl(fileDes, AES_DECRYPT, &dec_data)){
                    log_error("Giai ma that bai ");
                    goto close1;
                }

                printf("Nhap ten file giai ma: ");
                enterString(decFileName, MAX_INPUT_SIZE);
                file = fopen(decFileName, "w");
                if(!file){
                    printf("Khong the mo file giai ma\n");
                    break;
                }
                dec_data.file_size = strlen(dec_data.file_content);
                bytesWrite = fwrite(dec_data.file_content, 1, dec_data.file_size, file);
                if(bytesWrite != dec_data.file_size){
                    log_error("Loi ghi 1 phan");
                    goto close1;
                }
                printf("Giai ma thanh cong\n");
            close1:    
                close(fileDes);
            f_close1:
                fclose(file);       
                break;
            }
            case '9' : {
                goto out;
            }
            default : {
                printf("Khong co lua chon nay\n");
                break;
            }
        }
        printf("Nhan phim bat ki de tiep tuc\n");
        getchar();
        
    }
out:
    free(dec_data.file_content);
    free(dec_data.encrypted_file_content);
    free(enc_data.file_content);
    free(enc_data.encrypted_file_content);
    free(currentDir);
    free(dirName);
    free(fileName);
    free(encFileName);
    free(decFileName);
    close(fd);
}

