/*
 * Markus Moeller has modified the following code from Squid
 */

void ska_base64_decode(char* result, const char *data, int result_size);
void ska_base64_encode(char* result, const char *data, int result_size, int data_size);

int ska_base64_encode_len(int len);
int ska_base64_decode_len(const char *data);
