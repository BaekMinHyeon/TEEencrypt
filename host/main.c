/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	FILE *file;
	uint32_t encrypted_randomkey;
	char *option = argv[1];
	char *algorithm = argv[3];
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];

	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	
	if(strcmp(option, "-e") == 0){
		if(strcmp(algorithm, "Caesar") == 0) {
			printf("========================Caesar Encryption========================\n");
			file = fopen(argv[2], "r"); // file read
			fgets(plaintext, sizeof(plaintext), file);
			printf("Plaintext: %s\n", plaintext);
			memcpy(op.params[0].tmpref.buffer, plaintext, len);
			fclose(file);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);		

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			printf("Ciphertext : %s\n", ciphertext);
			
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);
			encrypted_randomkey = op.params[1].value.a;
			printf("Encrypted_randomkey : %u\n", encrypted_randomkey);
			
			file = fopen("ciphertext.txt", "w");
			fputs(ciphertext, file);
			printf("ciphertext.txt created\n");
			fclose(file);
			
			file = fopen("encryptedkey.txt", "w");
				
			fprintf(file, "%d", encrypted_randomkey);
			printf("encryptedkey.txt created\n");
			fclose(file);
		}
		else if(strcmp(algorithm, "RSA") == 0) {
			op.params[2].tmpref.buffer = clear;
			op.params[2].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			op.params[3].tmpref.buffer = ciph;
			op.params[3].tmpref.size = RSA_CIPHER_LEN_1024;

			printf("========================RSA Encryption========================\n");

			file = fopen(argv[2], "r");
			fgets(plaintext, sizeof(plaintext), file);
			printf("Plaintext: %s\n", plaintext);
			memcpy(op.params[2].tmpref.buffer, plaintext, len);
			fclose(file);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_GENKEYS, NULL, NULL);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
			printf("\n=========== Keys already generated. ==========\n");
			
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENC_VALUE, &op, &err_origin);

			memcpy(ciph, op.params[3].tmpref.buffer, RSA_CIPHER_LEN_1024);

			printf("Ciphertext : %s\n", ciph);
			
			file = fopen("RSA_ciphertext.txt","w");
			fputs(ciph, file);
			printf("RSA_ciphertext.txt is created\n");

			fclose(file);
		}
	}
	
	else if(strcmp(option, "-d") == 0) {
		printf("========================Caesar Decryption========================\n");
		file = fopen(argv[2], "r");
		fgets(ciphertext, sizeof(ciphertext), file);
		printf("Ciphertext: %s\n", ciphertext);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		fclose(file);
		
		file = fopen(argv[3], "r");
		fscanf(file, "%d", &encrypted_randomkey);
		op.params[1].value.a = encrypted_randomkey;
		printf("encrypted_randomkey: %u\n", encrypted_randomkey);
		fclose(file);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		file = fopen("Caesar_plaintext.txt", "w");
		fputs(plaintext, file);
		printf("Caesar_plaintext.txt created\n");
		fclose(file);		
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
