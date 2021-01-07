#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tprotected_fs.h>
#include <sgx_cpuid.h>
#include <sgx_utils.h>
#include <sgx_report.h>
#include <sgx_tseal.h>
 

#define PRINTF_BUFSIZE          256
#define BUF_SIZE                4096

int printf(const char* fmt, ...) {
    char buf[PRINTF_BUFSIZE] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, PRINTF_BUFSIZE, fmt, args);
    va_end(args);
    ocall_print(buf);
    return 0;
}

int open(const char* path) {
    int fd = 0;
    ocall_open(&fd, path);
    return fd;
}

int create(const char* path) {
    int fd = 0;
    ocall_create(&fd, path);
    return fd;
}

ssize_t read(int fd, void* buf, size_t size) {
    ssize_t ret = 0;
    ocall_read(&ret, fd, buf, size);
    return ret;
}

ssize_t write(int fd, const void* buf, size_t size) {
    ssize_t ret = 0;
    ocall_write(&ret, fd, buf, size);
    return ret;
}

int close(int fd) {
    int ret = 0;
    ocall_close(&ret, fd);
    return ret;
}

int ecall_encrypt_file(const char* _input_file,
                        const char* username
                        )
{
	// Generate report
	sgx_report_t report;
    memset(&report,0,sizeof(report));
    sgx_status_t ret = sgx_create_report(NULL,NULL,&report);
	// Report|username
	const char* ptr = "wuliangshun";
    uint8_t *p_src = (uint8_t*)malloc(2*sizeof(report));
    memset(p_src, 0, 2*sizeof(report));
    // copy Report
    memcpy(p_src, &report, sizeof(report));
    // copy *ptr
    memcpy(p_src + sizeof(report), ptr, sizeof(report));
	
	// 128bit cmac 
    sgx_cmac_128bit_tag_t *p_mac;
	sgx_status_t ret_cmac = sgx_rijndael128_cmac_msg(NULL, p_src, 2*sizeof(report), p_mac);
	if(ret_cmac < 0)
	{
		printf("Error: cmac fail!\n");
		return -1;
	}
	//printf("cmac_128bit:%d, size:%d,%d\n", *p_mac, sizeof(sgx_cmac_128bit_tag_t), sizeof(sgx_key_128bit_t));
	free(p_src);
    p_src = NULL;
	printf("128bit cmac generated successfully!\n");
	
	// 128bit key
	sgx_key_128bit_t key_128bit = {0};
    //memcpy(&key_128bit, p_mac, sizeof(sgx_key_128bit_t));
	//printf("Copy cmac to Key_128bit successfully!\n");

    int input_file = open(_input_file);
    if (input_file < 0) return -1;
	
	//outputfile 
	char _output_file[1024] = "encrypted_";
	strncat(_output_file, _input_file, strlen(_input_file));

    SGX_FILE* output_file = sgx_fopen(_output_file, "w", &key_128bit);
    if (output_file == NULL) {
        close(input_file);
        return -1;
    }

    ssize_t len;
    char buf[BUF_SIZE];
    while ((len = read(input_file, buf, BUF_SIZE)) > 0) {
        sgx_fwrite(buf, 1, len, output_file);
    }

    close(input_file);
    sgx_fclose(output_file);
    return 0;
	//sgx_fwrite(output_fp, BUF_SIZE, len, buf);
}

int ecall_decrypt_file(const char* _input_file,
                        const char* username)
{
   
	// Generate report
	sgx_report_t report;
    memset(&report,0,sizeof(report));
    sgx_status_t ret = sgx_create_report(NULL,NULL,&report);
	//printf("mr_enclave: %x\n", report.body.mr_enclave);
    //printf("mr_signer: %x\n", report.body.mr_signer);
	// Report|username
	const char* ptr = "wuliangshun";
    uint8_t *p_src = (uint8_t*)malloc(2*sizeof(report));
    memset(p_src, 0, 2*sizeof(report));
    // copy Report
    memcpy(p_src, &report, sizeof(report));
    // copy *ptr
    memcpy(p_src + sizeof(report), ptr, sizeof(report));
	
	// 128bit cmac 
    sgx_cmac_128bit_tag_t *p_mac;
	sgx_status_t ret_cmac = sgx_rijndael128_cmac_msg(NULL, p_src, 2*sizeof(report), p_mac);
	if(ret_cmac < 0)
	{
		printf("Error: cmac fail!\n");
		return -1;
	}
	//printf("cmac_128bit:%d, size:%d,%d\n", *p_mac, sizeof(sgx_cmac_128bit_tag_t), sizeof(sgx_key_128bit_t));
	free(p_src);
    p_src = NULL;
	printf("128bit cmac generated successfully!\n");
	
	// 128bit key
	sgx_key_128bit_t key_128bit = {0};
    //memcpy(&key_128bit, p_mac, sizeof(sgx_key_128bit_t));
	//printf("Copy cmac to Key_128bit successfully!\n");
	
	// Open file
	SGX_FILE* input_file = sgx_fopen(_input_file, "r", &key_128bit);
    if (input_file == NULL) return -1;

	// Audit rules
    ssize_t len;
    char buf[BUF_SIZE];
    while ((len = sgx_fread(buf, 1, BUF_SIZE, input_file)) > 0) {
		printf("\n content:%s\n", buf);
		if(strstr(buf, "illegal"))
			printf("\n Audit Fail !\n");
		else
			printf("\n Pass Audit! Congratulations!\n");
    }
    sgx_fclose(input_file);
	
    return 0;
}
