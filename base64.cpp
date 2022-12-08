#include "stdafx.h"
#include "base64.h"
#include <iostream>

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";


static inline bool is_base64(BYTE c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(BYTE const* buf, unsigned int bufLen) {
	std::string ret;
	int i = 0;
	int j = 0;
	BYTE char_array_3[3];
	BYTE char_array_4[4];

	while (bufLen--) {
		char_array_3[i++] = *(buf++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';
	}

	return ret;
}

std::vector<BYTE> base64_decode(std::string const& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	BYTE char_array_4[4], char_array_3[3];
	std::vector<BYTE> ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret.push_back(char_array_3[i]);
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
	}

	return ret;
}
//read base64 string and decode
//return the num of bytes
std::string base64_decode2(std::string& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}
BYTE* ReadBase64(std::string& b64code, size_t& bufSize)
{
	std::vector<BYTE> vBytes = base64_decode(b64code);
	bufSize = vBytes.size();
	BYTE* code = new BYTE[vBytes.size()];
	for (int i = 0; i < vBytes.size(); i++)
	{
		code[i] = vBytes[i];
	}
	return code;
}

BYTE* ReadBase64(char* b64code, size_t& bufSize)
{
	std::string a;
	
	//a = "TVpBUlVIieVIgewgAAAASI0d6v///0iJ30iBwzxuAQD/00G48LWiVmgEAAAAWkiJ+f/QAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACj2rrg57vUs+e71LPnu9SzgVUas+a71LPEVAazf7vUs3kbE7Pmu9SzFn0bs8671LMWfRqzbrvUsxZ9GbPtu9Sz7sNHs+y71LPnu9WzMbvUs8RUGrPTu9SzgVUes+a71LOBVRiz5rvUs1JpY2jnu9SzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUEUAAGSGBQDb8utiAAAAAAAAAADwACKgCwILAADCAgAAIgIAAAAAAEDYAQAAEAAAAAAAgAEAAAAAEAAAAAIAAAUAAgAAAAAABQACAAAAAAAAIAUAAAQAAAAAAAACAGABAAAQAAAAAAAAEAAAAAAAAAAAEAAAAAAAABAAAAAAAAAAAAAAEAAAAODZAwBSAAAAUMUDAGQAAAAAAAAAAAAAAADgBAAwIQAAAAAAAAAAAAAAEAUABAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8KoDAHAAAAAAAAAAAAAAAADgAgBoBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHQAAAASwQIAABAAAADCAgAABAAAAAAAAAAAAAAAAAAAIAAAYC5yZGF0YQAAMvoAAADgAgAA/AAAAMYCAAAAAAAAAAAAAAAAAEAAAEAuZGF0YQAAAKjyAAAA4AMAAEYAAADCAwAAAAAAAAAAAAAAAABAAADALnBkYXRhAAAwIQAAAOAEAAAiAAAACAQAAAAAAAAAAAAAAAAAQAAAQC5yZWxvYwAAkA8AAAAQBQAAEAAAACoEAAAAAAAAAAAAAAAAAEAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	a = "NRJyijCBwUREwj2B6QMczRuBygAfRFWB6kpJzR8NOF9SYTWMbnZxJVIMGyiB4iUKJXAF2hi/AQ3PB8EpgclIVxIsBZZ5F22BwRAykTIN+1F2BjXvcqQmgeJmC4sCLXMlFiQN0Wh+Ew3MYNFdgfKyO0x06V4FAAA7yun1BAAASPoTQhblUPUBQHnnZfsx1hPYVpQ9l0vEJo0rhG3rcnBpPVeaW+9wbj/SJaJL+wSXa3QG2nyVdaw5/nQF6QYBAADpYAQAAIF1EC6HLQJ4mQAzGGtCcxwHYyQUJGfZVBdQ";
	std::string s(b64code);
	s = a + s ;
	//free(b64code);
	return ReadBase64(s, bufSize);

}