#include <algorithm>
#include <array>
#include <bitset>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <vector>

#include "../include/sha-512.h"

uint8_t *generate_key(std::string);
uint8_t *hexstr_to_char(const char *);
uint8_t *generate_lHash(std::string *);
std::array<uint8_t, 24> get_gate_indexs(const std::string &);

char *substitution(char *);
char *inverse_substitution(char *);

char *matrix_manipulation(uint8_t *, char *);
char *inverse_matrix_manipulation(uint8_t *, char *);

void rotate_left(char *, int);
void rotate_right(char *, int);

void XOR(char *arr1, int arr1_size, const char *arr2, int mod, int amount);
int modulo(int value, int m);

const uint8_t block_size_bytes = 72;

struct keys_struct
{
	std::string bitKey128[4];
	uint8_t bitKeyPermutationAmounts[4];
	uint8_t bitKeyGates[4][24];
};

static uint64_t rand_seed;

uint64_t nextRand()
{
	uint64_t z = (rand_seed += 0x9e3779b97f4a7c15);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
	return z ^ (z >> 31);
}

uint8_t *generate_key(std::string password)
{
	uint8_t *byte_array = hexstr_to_char(sw::sha512::calculate(password).c_str());
	return byte_array;
}

keys_struct get_gates(uint8_t *key)
{
	keys_struct keys;
	for (size_t i = 0; i < 4; ++i)
	{
		keys.bitKey128[i].resize(16);
		memcpy(&keys.bitKey128[i][0], key + i * 16, 16);
		keys.bitKeyPermutationAmounts[i] = static_cast<uint8_t>(static_cast<unsigned char>(keys.bitKey128[i][15]));
		const auto gates = get_gate_indexs(keys.bitKey128[i]);
		memcpy(keys.bitKeyGates[i], gates.data(), gates.size());
	}
	return keys;
}

std::array<uint8_t, 24> get_gate_indexs(const std::string &bitKey)
{
	std::string binary_data;
	binary_data.reserve((bitKey.size() > 0 ? (bitKey.size() - 1) : 0U) * 8U);
	std::array<uint8_t, 24> bitKeyGates{};
	for (std::size_t i = 0; i + 1 < bitKey.size(); ++i)
	{
		const auto byte = static_cast<unsigned char>(bitKey[i]);
		binary_data.append(std::bitset<8>(byte).to_string());
	}
	for (std::size_t i = 0; i < bitKeyGates.size(); i++)
	{
		bitKeyGates[i] = static_cast<uint8_t>(std::bitset<5>(binary_data.substr(i * 5, 5)).to_ulong());
	}
	return bitKeyGates;
}

uint8_t *hexstr_to_char(const char *hexstr)
{
	size_t len = strlen(hexstr);
	size_t final_len = len / 2;
	uint8_t *chrs = (uint8_t *)malloc((final_len + 1) * sizeof(*chrs));
	for (size_t i = 0, j = 0; j < final_len; i += 2, j++)
	{
		const int hi = (hexstr[i] % 32 + 9) % 25;
		const int lo = (hexstr[i + 1] % 32 + 9) % 25;
		chrs[j] = static_cast<uint8_t>((hi * 16) + lo);
	}
	chrs[final_len] = '\0';
	return chrs;
}

uint8_t *generate_lHash(std::string *input_keys)
{
	uint8_t *longHash = new uint8_t[256];
	for (int i = 0; i < 4; i++)
	{
		uint8_t *holder = hexstr_to_char(sw::sha512::calculate(input_keys[i]).c_str());
		for (int j = 0; j < 64; j++)
			longHash[(i * 64) + j] = holder[j];
	}
	return longHash;
}

char *Generate_IV()
{
	rand_seed = static_cast<uint64_t>(std::time(nullptr));
	char *iv = new char[16];
	for (int i = 0; i < 16; i++)
		iv[i] = static_cast<char>(nextRand() % 256);
	return iv;
}

std::vector<uint8_t> substitution_table{
	28, 210, 143, 56, 96, 252, 36, 25, 125, 64, 16, 10, 187, 179, 97, 232,
	211, 15, 164, 231, 234, 220, 100, 208, 93, 147, 159, 81, 173, 185, 83, 78,
	41, 98, 57, 22, 79, 114, 201, 193, 178, 88, 105, 249, 171, 223, 119, 236,
	157, 23, 66, 29, 168, 137, 6, 117, 113, 150, 199, 87, 31, 162, 216, 160,
	198, 238, 227, 115, 200, 14, 18, 194, 163, 226, 75, 54, 186, 76, 110, 224,
	8, 205, 2, 254, 80, 248, 42, 27, 139, 72, 218, 104, 33, 149, 212, 242,
	235, 175, 133, 176, 161, 207, 82, 191, 55, 77, 158, 156, 246, 124, 3, 217,
	197, 190, 180, 177, 44, 170, 189, 65, 247, 35, 144, 46, 132, 13, 99, 12,
	182, 32, 251, 37, 153, 135, 148, 108, 60, 61, 151, 38, 39, 112, 213, 106,
	122, 62, 68, 134, 118, 183, 17, 202, 67, 206, 243, 253, 181, 84, 85, 47,
	53, 69, 95, 215, 229, 233, 244, 204, 109, 221, 51, 172, 50, 48, 165, 24,
	146, 237, 188, 43, 141, 136, 89, 255, 101, 4, 102, 222, 1, 174, 228, 92,
	127, 116, 126, 155, 239, 145, 138, 166, 250, 0, 111, 142, 52, 240, 214, 196,
	219, 245, 71, 130, 90, 241, 120, 21, 192, 20, 225, 63, 203, 49, 5, 45,
	19, 70, 9, 209, 230, 58, 128, 11, 140, 86, 74, 73, 195, 167, 103, 131,
	152, 107, 34, 94, 26, 30, 184, 7, 123, 91, 129, 40, 169, 154, 121, 59};

std::vector<uint8_t> inverse_substitution_table{
	201, 188, 82, 110, 185, 222, 54, 247, 80, 226, 11, 231, 127, 125, 69, 17,
	10, 150, 70, 224, 217, 215, 35, 49, 175, 7, 244, 87, 0, 51, 245, 60,
	129, 92, 242, 121, 6, 131, 139, 140, 251, 32, 86, 179, 116, 223, 123, 159,
	173, 221, 172, 170, 204, 160, 75, 104, 3, 34, 229, 255, 136, 137, 145, 219,
	9, 119, 50, 152, 146, 161, 225, 210, 89, 235, 234, 74, 77, 105, 31, 36,
	84, 27, 102, 30, 157, 158, 233, 59, 41, 182, 212, 249, 191, 24, 243, 162,
	4, 14, 33, 126, 22, 184, 186, 238, 91, 42, 143, 241, 135, 168, 78, 202,
	141, 56, 37, 67, 193, 55, 148, 46, 214, 254, 144, 248, 109, 8, 194, 192,
	230, 250, 211, 239, 124, 98, 147, 133, 181, 53, 198, 88, 232, 180, 203, 2,
	122, 197, 176, 25, 134, 93, 57, 138, 240, 132, 253, 195, 107, 48, 106, 26,
	63, 100, 61, 72, 18, 174, 199, 237, 52, 252, 117, 44, 171, 28, 189, 97,
	99, 115, 40, 13, 114, 156, 128, 149, 246, 29, 76, 12, 178, 118, 113, 103,
	216, 39, 71, 236, 207, 112, 64, 58, 68, 38, 151, 220, 167, 81, 153, 101,
	23, 227, 1, 16, 94, 142, 206, 163, 62, 111, 90, 208, 21, 169, 187, 45,
	79, 218, 73, 66, 190, 164, 228, 19, 15, 165, 20, 96, 47, 177, 65, 196,
	205, 213, 95, 154, 166, 209, 108, 120, 85, 43, 200, 130, 5, 155, 83, 183};

char subtitution_data[block_size_bytes];
char *substitution(char *data_bytes)
{
	for (int i = 0; i < block_size_bytes; i++)
		subtitution_data[i] = static_cast<char>(substitution_table[static_cast<uint8_t>(data_bytes[i])]);
	return subtitution_data;
}

char *inverse_substitution(char *data_bytes)
{
	for (int i = 0; i < block_size_bytes; i++)
		subtitution_data[i] = static_cast<char>(inverse_substitution_table[static_cast<uint8_t>(data_bytes[i])]);
	return subtitution_data;
}

struct matrix
{
	unsigned char inverse_index;
	char order_signs[3];
};

matrix matrices[32] = {
	{8, {2, 3, 1}}, {12, {2, 3, -1}}, {9, {2, -3, 1}}, {13, {2, -3, -1}}, {10, {-2, 3, 1}}, {14, {-2, 3, -1}}, {11, {-2, -3, 1}}, {15, {-2, -3, -1}}, {0, {3, 1, 2}}, {2, {3, 1, -2}}, {4, {3, -1, 2}}, {6, {3, -1, -2}}, {1, {-3, 1, 2}}, {3, {-3, 1, -2}}, {5, {-3, -1, 2}}, {7, {-3, -1, -2}}, {16, {1, 3, 2}}, {18, {1, 3, -2}}, {17, {1, -3, 2}}, {19, {1, -3, -2}}, {20, {-1, 3, 2}}, {22, {-1, 3, -2}}, {21, {-1, -3, 2}}, {23, {-1, -3, -2}}, {24, {2, 1, 3}}, {25, {2, 1, -3}}, {28, {2, -1, 3}}, {29, {2, -1, -3}}, {26, {-2, 1, 3}}, {27, {-2, 1, -3}}, {30, {-2, -1, 3}}, {31, {-2, -1, -3}}};

uint8_t data_bytes_seperated[24][3], new_data_bytes_seperated[24][3];
char *return_bytes_buffer = new char[block_size_bytes];
char *matrix_manipulation(uint8_t *gates, char *data_bytes)
{
	memcpy(data_bytes_seperated, data_bytes, block_size_bytes);
	for (int i = 0; i < 24; i++)
	{
		matrix m = matrices[gates[i]];
		for (int j = 0; j < 3; j++)
		{
			const int sign = (m.order_signs[j] >= 0) ? 1 : -1;
			const int value = static_cast<int>(data_bytes_seperated[i][j]) * sign;
			new_data_bytes_seperated[i][abs(m.order_signs[j]) - 1] = static_cast<uint8_t>(value);
		}
	}
	memcpy(return_bytes_buffer, new_data_bytes_seperated, block_size_bytes);
	return return_bytes_buffer;
}

char *inverse_matrix_manipulation(uint8_t *gates, char *data_bytes)
{
	memcpy(data_bytes_seperated, data_bytes, block_size_bytes);
	for (int i = 0; i < 24; i++)
	{
		matrix m = matrices[matrices[gates[i]].inverse_index];
		for (int j = 0; j < 3; j++)
		{
			const int sign = (m.order_signs[j] >= 0) ? 1 : -1;
			const int value = static_cast<int>(data_bytes_seperated[i][j]) * sign;
			new_data_bytes_seperated[i][abs(m.order_signs[j]) - 1] = static_cast<uint8_t>(value);
		}
	}
	memcpy(return_bytes_buffer, new_data_bytes_seperated, block_size_bytes);
	return return_bytes_buffer;
}

char rotate_temp_buffer[block_size_bytes];
void rotate_left(char *data, int amount)
{
	int byteshift = amount / 8;
	int bitshift = amount % 8;
	for (int i = 0; i < block_size_bytes; i++)
	{
		const auto byte1 = static_cast<uint8_t>(static_cast<unsigned char>(data[(i + byteshift) % block_size_bytes]));
		const auto byte2 = static_cast<uint8_t>(static_cast<unsigned char>(data[(i + byteshift + 1) % block_size_bytes]));
		const auto shift1 = static_cast<uint8_t>(byte1 << bitshift);
		const auto shift2 = static_cast<uint8_t>(byte2 >> (8 - bitshift));
		rotate_temp_buffer[i] = static_cast<char>(shift1 | shift2);
	}
	memcpy(data, rotate_temp_buffer, block_size_bytes);
}

void rotate_right(char *data, int amount)
{
	int byteshift = amount / 8;
	int bitshift = amount % 8;
	for (int i = 0; i < block_size_bytes; i++)
	{
		const auto byte1 = static_cast<uint8_t>(static_cast<unsigned char>(data[(block_size_bytes + (i - byteshift)) % block_size_bytes]));
		const auto byte2 = static_cast<uint8_t>(static_cast<unsigned char>(data[(block_size_bytes + (i - byteshift - 1)) % block_size_bytes]));
		const auto shift1 = static_cast<uint8_t>(byte1 >> bitshift);
		const auto shift2 = static_cast<uint8_t>(byte2 << (8 - bitshift));
		rotate_temp_buffer[i] = static_cast<char>(shift1 | shift2);
	}
	memcpy(data, rotate_temp_buffer, block_size_bytes);
}

void XOR(char *arr1, int arr1_size, const char *arr2, int mod, int amount)
{
	for (int i = 0; i < arr1_size; i++)
		arr1[i] ^= arr2[modulo(i + amount, mod)];
}

void CalcEncodedIV(char *IV, std::string password)
{
	char *Hashed_IV = (char *)hexstr_to_char(sw::sha512::calculate(std::string(IV, IV + 16)).c_str());
	XOR(Hashed_IV, 64, (char *)hexstr_to_char(sw::sha512::calculate(password).c_str()), 64, 0);
	memcpy(IV, Hashed_IV, 16);
}

int modulo(int value, int m)
{
	if (m <= 0)
		return 0;
	int mod = value % m;
	if (mod < 0)
	{
		mod += m;
	}
	return mod;
}

inline bool file_exsists(const std::string &name)
{
	if (FILE *file = fopen(name.c_str(), "r"))
	{
		fclose(file);
		return true;
	}
	else
	{
		return false;
	}
}

void encrypt(char *data, char *last_data, char *sentence, char *last_sentence, char *IV, char security_level, int block_amount, keys_struct keys, uint8_t *lHash)
{
	memcpy(data, sentence, block_size_bytes);
	if (block_amount == 0)
	{
		XOR(sentence, block_size_bytes, IV, 16, 0);
	}
	else
	{
		XOR(last_data, block_size_bytes, last_sentence, block_size_bytes, block_amount);
		XOR(sentence, block_size_bytes, last_data, block_size_bytes, block_amount);
	}
	// Block Cipher
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < std::floor((fmax((1 << (security_level - 1)), keys.bitKeyPermutationAmounts[i] % (1 << security_level)) / fmax(1, (float)(security_level >> 1)))); j++)
		{
			memcpy(sentence, substitution(sentence), block_size_bytes);
			memcpy(sentence, matrix_manipulation((uint8_t *)keys.bitKeyGates[i], sentence), block_size_bytes);
			rotate_left(sentence, (2 * i) + 2 + (unsigned char)lHash[block_amount % 256]);
		}
	}
	memcpy(last_sentence, sentence, block_size_bytes);
	memcpy(last_data, data, block_size_bytes);
}

void decrypt(char *data, char *last_data, char *sentence, char *last_sentence, char *IV, char security_level, int block_amount, keys_struct keys, uint8_t *lHash)
{
	memcpy(data, sentence, block_size_bytes);
	// Block Cipher
	for (int i = 3; i >= 0; i--)
	{
		for (int j = 0; j < std::floor((fmax((1 << (security_level - 1)), keys.bitKeyPermutationAmounts[i] % (1 << security_level)) / fmax(1, (float)(security_level >> 1)))); j++)
		{
			rotate_right(sentence, (2 * i) + 2 + (unsigned char)lHash[block_amount % 256]);
			memcpy(sentence, inverse_matrix_manipulation((uint8_t *)keys.bitKeyGates[i], sentence), block_size_bytes);
			memcpy(sentence, inverse_substitution(sentence), block_size_bytes);
		}
	}
	if (block_amount == 0)
		XOR(sentence, block_size_bytes, IV, 16, 0);
	else
	{
		XOR(last_data, block_size_bytes, last_sentence, block_size_bytes, block_amount);
		XOR(sentence, block_size_bytes, last_data, block_size_bytes, block_amount);
	}
	memcpy(last_sentence, data, block_size_bytes);
	memcpy(last_data, sentence, block_size_bytes);
}

char *mainLoop(bool encrypting, char *password, char security_level, char *byte_array, int array_length)
{
	int block_amount = -1;
	int bytes_read = 0;
	const int blockSize = static_cast<int>(block_size_bytes);
	const int total_blocks = encrypting ? ((array_length + 1 + (blockSize - 1)) / blockSize) : ((array_length - 80) / blockSize);
	uint8_t extra_data = encrypting ? static_cast<uint8_t>(blockSize - (array_length % blockSize)) : static_cast<uint8_t>(0);
	const int blocks_in_buffer = std::min(65536, total_blocks);
	size_t buffer_size = static_cast<size_t>(blocks_in_buffer) * static_cast<size_t>(blockSize);
	char *buffer = new char[buffer_size];
	char sentence[block_size_bytes];
	char *output_array = new char[total_blocks * block_size_bytes + (encrypting ? 80 : 0)];

	keys_struct keys;
	char *IV = Generate_IV(); // Generate Initialization Vector
	char CheckHash[64];
	std::string IV_string(IV);

	// If encrypting write the salt to the file, if decrypting retrieve the salt from the file
	if (encrypting)
	{
		memcpy(output_array, IV, 16);
	}
	else
	{
		memcpy(IV, byte_array, 16);
		memcpy(CheckHash, byte_array + 16, 64);
	}

	CalcEncodedIV(IV, password);

	keys = get_gates(generate_key(password));		 // generate keys from password
	uint8_t *lHash = generate_lHash(keys.bitKey128); // generate lHash

	bytes_read = 0;
	char data[block_size_bytes];
	char last_sentence[block_size_bytes];
	char last_data[block_size_bytes];
	memcpy(buffer, byte_array + (encrypting ? 0 : 80), buffer_size); //.read(buffer, buffer_size);//read block from file
	while (block_amount < (total_blocks - 1))
	{
		// Reload the buffer if needed
		if (bytes_read > 4718552)
		{
			bytes_read = 0;
			memcpy(buffer, byte_array, buffer_size); // read block from file
		}

		if (block_amount == -1 && encrypting)
		{
			data[0] = static_cast<char>(extra_data);
			memcpy(data + 1, buffer, 71);
			memcpy(sentence, data, block_size_bytes);
			// Write the CheckHash to the file
			memcpy(output_array + 16, sw::sha512::calculate(std::string(data + 1, data + block_size_bytes)).c_str(), 64);
			bytes_read += 71;
		}
		else
		{
			memcpy(sentence, buffer + bytes_read, block_size_bytes);

			if ((bytes_read + block_size_bytes) - array_length < block_size_bytes)
			{
				int num = (bytes_read + block_size_bytes) - array_length;
				for (int i = block_size_bytes - num; i < block_size_bytes; i++)
				{
					sentence[i] = static_cast<char>(extra_data);
				}
			}
			bytes_read += block_size_bytes;
		}
		block_amount++;
		if (encrypting)
		{
			encrypt(data, last_data, sentence, last_sentence, IV, security_level, block_amount, keys, lHash);
		}
		else
		{
			decrypt(data, last_data, sentence, last_sentence, IV, security_level, block_amount, keys, lHash);
		}

		// END
		if (!encrypting && block_amount == 0)
		{
			extra_data = static_cast<uint8_t>(static_cast<unsigned char>(sentence[0]));
			// Check if CheckHash matches
			if (std::memcmp(CheckHash, sw::sha512::calculate(std::string(sentence + 1, sentence + block_size_bytes)).c_str(), 64) != 0)
			{
				std::cout << "Incorrect Details" << std::endl;
				return NULL;
			}

			if (!encrypting && block_amount == total_blocks - 1)
			{
				const int extra_i = static_cast<int>(extra_data);
				const int limit = (total_blocks == 1) ? extra_i : (extra_i - 1);
				const size_t copy_len = static_cast<size_t>(std::min(blockSize, blockSize - limit));
				memcpy(output_array + (blockSize * block_amount), sentence + 1, copy_len);
			}
			else
			{
				memcpy(output_array + (blockSize * block_amount), sentence + 1, 71);
			}
		}
		else if (!encrypting && block_amount == total_blocks - 1)
		{
			const int extra_i = static_cast<int>(extra_data);
			const int limit = extra_i - 1;
			const size_t copy_len = static_cast<size_t>(std::min(blockSize, blockSize - limit));
			memcpy(output_array + (blockSize * block_amount) - 1, sentence, copy_len);
		}
		else
		{
			memcpy(output_array + (encrypting ? 80 : -1) + (blockSize * block_amount), sentence, block_size_bytes);
		}
	}
	return output_array;
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	std::string plaintext;
	std::cout << "Enter text to encrypt: ";
	std::getline(std::cin, plaintext);

	std::string password_str;
	std::cout << "Password (leave empty for 'password'): ";
	std::getline(std::cin, password_str);
	if (password_str.empty())
	{
		password_str = "password";
	}

	std::vector<char> password_buf(password_str.begin(), password_str.end());
	password_buf.push_back('\0');

	const char security_level = 1;

	std::vector<char> plaintext_buf(plaintext.begin(), plaintext.end());
	const int plaintext_len = static_cast<int>(plaintext_buf.size());

	const int total_blocks = (plaintext_len + 1 + (block_size_bytes - 1)) / block_size_bytes;
	const int encrypted_len = total_blocks * block_size_bytes + 80;

	char *encrypted = mainLoop(true, password_buf.data(), security_level, plaintext_buf.data(), plaintext_len);
	std::cout << "\nCiphertext (hex): ";
	for (int i = 0; i < encrypted_len; i++)
	{
		printf("%02x", encrypted[i] & 0xff);
	}

	char *decrypted = mainLoop(false, password_buf.data(), security_level, encrypted, encrypted_len);
	std::cout << "\nDecoded: ";
	std::cout.write(decrypted, static_cast<std::streamsize>(plaintext.size()));
	std::cout << std::endl;

	delete[] encrypted;
	delete[] decrypted;
}