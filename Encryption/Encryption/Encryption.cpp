#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <chrono>
#include <stdlib.h>
#include "sha-512.h"

uint8_t* generate_key(std::string);
uint8_t* hexstr_to_char(const char*);
uint8_t* generate_lHash(std::string*);
std::vector<char> get_gate_indexs(std::string);
char* substitution(char*, bool);
char* pass_bytes_through_gates(uint8_t*, char*, bool);
void rotate(char*, bool, int);
void XOR(char*, char, char*, char, char);
unsigned modulo(int value, unsigned m);

struct keys_struct {
	std::string bitKey128[4];
	uint8_t bitKeyPermutationAmounts[4];
	uint8_t bitKeyGates[4][24];
};

static uint64_t rand_seed;

uint64_t nextRand() {
	uint64_t z = (rand_seed += 0x9e3779b97f4a7c15);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
	return z ^ (z >> 31);
}

uint8_t* generate_key(std::string password)
{
	uint8_t* byte_array = hexstr_to_char(sw::sha512::calculate(password).c_str());
	return byte_array;
}

keys_struct get_gates(uint8_t* key)
{
	keys_struct keys;
	for (size_t i = 0; i < 4; ++i) {
		keys.bitKey128[i].resize(16);
		memcpy(&keys.bitKey128[i][0], key + i * 16, 16);
		keys.bitKeyPermutationAmounts[i] = keys.bitKey128[i][15];
		memcpy(keys.bitKeyGates[i], get_gate_indexs(keys.bitKey128[i]).data(), 24);
	}
	return keys;
}

std::vector<char> get_gate_indexs(std::string bitKey)
{
	std::string binary_data;
	std::vector<char> bitKeyGates(24);
	for (std::size_t i = 0; i < bitKey.size() - 1; ++i)
		binary_data.append(std::bitset<8>(bitKey.c_str()[i]).to_string());
	for (size_t i = 0; i < 24; i++)
		bitKeyGates[i] = std::bitset<5>(binary_data.substr(i * 5, 5)).to_ulong();
	return bitKeyGates;
}

uint8_t* hexstr_to_char(const char* hexstr)
{
	size_t len = strlen(hexstr);
	size_t final_len = len / 2;
	uint8_t* chrs = (uint8_t*)malloc((final_len + 1) * sizeof(*chrs));
	for (size_t i = 0, j = 0; j < final_len; i += 2, j++)
		chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
	chrs[final_len] = '\0';
	return chrs;
}

uint8_t* generate_lHash(std::string* input_keys)
{
	uint8_t* longHash = new uint8_t[256];
	for (int i = 0; i < 4; i++)
	{
		uint8_t* holder = hexstr_to_char(sw::sha512::calculate(input_keys[i]).c_str());
		for (int j = 0; j < 64; j++)
			longHash[(i * 64) + j] = holder[j];
	}
	return longHash;
}

char* Generate_IV()
{
	rand_seed = std::time(0);
	char* iv = new char[16];
	for (int i = 0; i < 16; i++)
		iv[i] = nextRand() % 256;
	return iv;
}

std::vector<uint8_t> substitution_table{
	28,210,143,56,96,252,36,25,125,64,16,10,187,179,97,232,
	211,15,164,231,234,220,100,208,93,147,159,81,173,185,83,78,
	41,98,57,22,79,114,201,193,178,88,105,249,171,223,119,236,
	157,23,66,29,168,137,6,117,113,150,199,87,31,162,216,160,
	198,238,227,115,200,14,18,194,163,226,75,54,186,76,110,224,
	8,205,2,254,80,248,42,27,139,72,218,104,33,149,212,242,
	235,175,133,176,161,207,82,191,55,77,158,156,246,124,3,217,
	197,190,180,177,44,170,189,65,247,35,144,46,132,13,99,12,
	182,32,251,37,153,135,148,108,60,61,151,38,39,112,213,106,
	122,62,68,134,118,183,17,202,67,206,243,253,181,84,85,47,
	53,69,95,215,229,233,244,204,109,221,51,172,50,48,165,24,
	146,237,188,43,141,136,89,255,101,4,102,222,1,174,228,92,
	127,116,126,155,239,145,138,166,250,0,111,142,52,240,214,196,
	219,245,71,130,90,241,120,21,192,20,225,63,203,49,5,45,
	19,70,9,209,230,58,128,11,140,86,74,73,195,167,103,131,
	152,107,34,94,26,30,184,7,123,91,129,40,169,154,121,59
};

std::vector<uint8_t> inverse_substitution_table{
	201,188,82,110,185,222,54,247,80,226,11,231,127,125,69,17,
	10,150,70,224,217,215,35,49,175,7,244,87,0,51,245,60,
	129,92,242,121,6,131,139,140,251,32,86,179,116,223,123,159,
	173,221,172,170,204,160,75,104,3,34,229,255,136,137,145,219,
	9,119,50,152,146,161,225,210,89,235,234,74,77,105,31,36,
	84,27,102,30,157,158,233,59,41,182,212,249,191,24,243,162,
	4,14,33,126,22,184,186,238,91,42,143,241,135,168,78,202,
	141,56,37,67,193,55,148,46,214,254,144,248,109,8,194,192,
	230,250,211,239,124,98,147,133,181,53,198,88,232,180,203,2,
	122,197,176,25,134,93,57,138,240,132,253,195,107,48,106,26,
	63,100,61,72,18,174,199,237,52,252,117,44,171,28,189,97,
	99,115,40,13,114,156,128,149,246,29,76,12,178,118,113,103,
	216,39,71,236,207,112,64,58,68,38,151,220,167,81,153,101,
	23,227,1,16,94,142,206,163,62,111,90,208,21,169,187,45,
	79,218,73,66,190,164,228,19,15,165,20,96,47,177,65,196,
	205,213,95,154,166,209,108,120,85,43,200,130,5,155,83,183
};

char subtitution_data[72];
char* substitution(char* data_bytes, bool encoding)
{
	if (encoding)
		for (int i = 0; i < 72; i++)
			subtitution_data[i] = substitution_table[(uint8_t)data_bytes[i]];
	else
		for (int i = 0; i < 72; i++)
			subtitution_data[i] = inverse_substitution_table[(uint8_t)data_bytes[i]];
	return subtitution_data;
}

struct matrix
{
	unsigned char inverse_index;
	char order_signs[3];
};

matrix matrices[32] = {
	{8,{2,3,1}},{12,{2,3,-1}},{9,{2,-3,1}},{13,{2,-3,-1}},{10,{-2,3,1}},{14,{-2,3,-1}},{11,{-2,-3,1}},{15,{-2,-3,-1}},
	{0,{3,1,2}},{2,{3,1,-2}},{4,{3,-1,2}},{6,{3,-1,-2}},{1,{-3,1,2}},{3,{-3,1,-2}},{5,{-3,-1,2}},{7,{-3,-1,-2}},
	{16,{1,3,2}},{18,{1,3,-2}},{17,{1,-3,2}},{19,{1,-3,-2}},{20,{-1,3,2}},{22,{-1,3,-2}},{21,{-1,-3,2}},{23,{-1,-3,-2}},
	{24,{2,1,3}},{25,{2,1,-3}},{28,{2,-1,3}},{29,{2,-1,-3}},{26,{-2,1,3}},{27,{-2,1,-3}},{30,{-2,-1,3}},{31,{-2,-1,-3}}
};

uint8_t data_bytes_seperated[24][3], new_data_bytes_seperated[24][3];
char* return_bytes_buffer = new char[72];
char* pass_bytes_through_gates(uint8_t* gates, char* data_bytes, bool encoding)
{
	memcpy(data_bytes_seperated, data_bytes, 72);
	for (int i = 0; i < 24; i++)
	{
		matrix m = encoding ? matrices[gates[i]] : matrices[matrices[gates[i]].inverse_index];
		for (int j = 0; j < 3; j++)
			new_data_bytes_seperated[i][abs(m.order_signs[j]) - 1] = m.order_signs[j] < 0 ? -data_bytes_seperated[i][j] : data_bytes_seperated[i][j];
	}
	memcpy(return_bytes_buffer, data_bytes_seperated, 72);
	return return_bytes_buffer;
}

char rotate_temp_buffer[72];
void rotate(char* data, bool left, int amount)
{
	int byteshift = amount / 8;
	int bitshift = amount % 8;
	if (left)
		for (int i = 0; i < 72; i++) {
			unsigned char byte1 = data[(i + byteshift) % 72];
			unsigned char byte2 = data[(i + byteshift + 1) % 72];
			unsigned char shift1 = byte1 << bitshift;
			unsigned char shift2 = byte2 >> (8 - bitshift);
			rotate_temp_buffer[i] = shift1 | shift2;
		}
	else
		for (int i = 0; i < 72; i++) {
			unsigned char byte1 = data[(72 + (i - byteshift)) % 72];
			unsigned char byte2 = data[(72 + (i - byteshift - 1)) % 72];
			unsigned char shift1 = byte1 >> bitshift;
			unsigned char shift2 = byte2 << (8 - bitshift);
			rotate_temp_buffer[i] = shift1 | shift2;
		}
	memcpy(data, rotate_temp_buffer, 72);
}

void XOR(char* arr1, char arr1_size, char* arr2, char mod, char amount)
{
	for (int i = 0; i < arr1_size; i++)
		arr1[i] ^= arr2[modulo((i + amount), mod)];
}

unsigned modulo(int value, unsigned m) {
	int mod = value % (int)m;
	if (mod < 0) {
		mod += m;
	}
	return mod;
}

inline bool file_exsists(const std::string& name) {
	if (FILE* file = fopen(name.c_str(), "r")) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}

int main(int argc, char** argv)
{
	bool encrypting;
	//check if correct args
	if (argc < 5) {
		std::cout << "Incorrect Auguments, Try: Encryption.exe [password] [encryption] [security] [file_path] [-d].\n\n"
			<< "Password (string)\n"
			<< "Encrypting (string: true/false)\n"
			<< "Security Level (int)\n"
			<< "File Name (string). without siffix .pdea\n"
			<< "-d Delete original file, not needed if you want to keep original file.";
		return -1;
	}

	std::istringstream(argv[2]) >> std::boolalpha >> encrypting;
	std::string first_file = argv[4]; //Unencrypted File Name
	std::string second_file = first_file + ".pdea"; //Encrypted File Name

	//Check if file exsists
	if (!file_exsists(encrypting ? first_file : second_file)) {
		std::cout << "File: " << argv[4] << " doesnt appear to exist." << std::endl;
		return -1;
	}

	//Load File
	std::ifstream bytes_file(encrypting ? first_file : second_file, std::ios_base::binary);
	bytes_file.seekg(0, std::ios::end);
	size_t length = bytes_file.tellg();
	bytes_file.seekg(0, std::ios::beg);
	int block_amount = -1;
	int bytes_read = 0;
	int total_blocks = encrypting ? ceil((length + 1) / 72.0f) : ((length - 80) / 72);
	char extra_data = encrypting ? 72 - (length % 72) : 0;
	size_t buffer_size = fmin(65536, total_blocks) * 72;
	char* buffer = new char[buffer_size];
	std::fstream ofs(encrypting ? second_file : first_file, std::fstream::out | std::fstream::trunc);
	ofs.close();
	auto append_file = std::fopen(std::string(encrypting ? second_file : first_file).c_str(), "wb");
	char sentence[72];

	keys_struct keys;
	char* IV = Generate_IV();//Generate Initialization Vector
	char CheckHash[64];
	std::string IV_string(IV);

	//If encrypting write the salt to the file, if decrypting retrieve the salt from the file
	if (encrypting) {
		fwrite(IV, 1, 16, append_file);
	}
	else {
		bytes_file.read(buffer, 16);
		memcpy(IV, buffer, 16);
		bytes_file.read(buffer, 64);
		memcpy(CheckHash, buffer, 64);
	}

	std::string test(argv[1]);
	keys = get_gates(generate_key(test)); //generate keys from password
	uint8_t* lHash = generate_lHash(keys.bitKey128); //generate lHash
	char security_level = strtol(argv[3], NULL, 10); //Level of security

	bytes_read = 0;
	char data[72];
	char last_sentence[72];
	char last_data[72];
	bytes_file.read(buffer, buffer_size);//read block from file
	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	while (block_amount < (total_blocks - 1))
	{
		//Reload the buffer if needed
		if (bytes_read > 4718552) {
			bytes_read = 0;
			bytes_file.read(buffer, buffer_size);//read block from file
		}

		if (block_amount == -1 && encrypting)
		{
			data[0] = { extra_data };
			memcpy(data + 1, buffer, 71);
			memcpy(sentence, data, 72);
			//Write the CheckHash to the file
			fwrite(hexstr_to_char(sw::sha512::calculate(std::string(data + 1, data + 72)).c_str()), 1, 64, append_file);
			bytes_read += 71;
		}
		else
		{
			memcpy(sentence, buffer + bytes_read, 72);

			if ((bytes_read + 72) - length < 72) {
				char num = (bytes_read + 72) - length;
				for (int i = 72 - num; i < 72; i++) {
					sentence[i] = extra_data;
				}
			}
			bytes_read += 72;
		}
		block_amount++;
		if (encrypting)
		{
			memcpy(data, sentence, 72);
			if (block_amount == 0) {
				XOR(sentence, 72, IV, 16, 0);
			} else {
				XOR(last_data, 72, last_sentence, 72, block_amount);
				XOR(sentence, 72, last_data, 72, block_amount);
			}
			//Block Cipher
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < std::floor((fmax((1 << (security_level - 1)), keys.bitKeyPermutationAmounts[i] % (1 << security_level)) / fmax(1, (float)(security_level >> 1)))); j++)
				{
					memcpy(sentence, substitution(sentence, true), 72);
					memcpy(sentence, pass_bytes_through_gates((uint8_t*)keys.bitKeyGates[i], sentence, true), 72);
					rotate(sentence, true, (2 * i) + 2 + (unsigned char)lHash[block_amount % 256]);
				}
			}
			memcpy(last_sentence, sentence, 72);
			memcpy(last_data, data, 72);
		}
		else
		{
			memcpy(data, sentence, 72);
			//Block Cipher
			for (int i = 3; i >= 0; i--) {
				for (int j = 0; j < std::floor((fmax((1 << (security_level - 1)), keys.bitKeyPermutationAmounts[i] % (1 << security_level)) / fmax(1, (float)(security_level >> 1)))); j++)
				{
					rotate(sentence, false, (2 * i) + 2 + (unsigned char)lHash[block_amount % 256]);
					memcpy(sentence, pass_bytes_through_gates((uint8_t*)keys.bitKeyGates[i], sentence, false), 72);
					memcpy(sentence, substitution(sentence, false), 72);
				}
			}
			if (block_amount == 0)
				XOR(sentence, 72, IV, 16, 0);
			else {
				XOR(last_data, 72, last_sentence, 72, block_amount);
				XOR(sentence, 72, last_data, 72, block_amount);
			}
			memcpy(last_sentence, data, 72);
			memcpy(last_data, sentence, 72);
		}
		if (!encrypting && block_amount == 0)
		{
			extra_data = sentence[0];
			//Check if CheckHash matches
			if (std::memcmp(CheckHash, hexstr_to_char(sw::sha512::calculate(std::string(sentence + 1, sentence + 72)).c_str()), 64) != 0) {
				std::cout << "Incorrect Details" << std::endl;
				fclose(append_file);
				remove(first_file.c_str());
				return -1;
			}

			if (!encrypting && block_amount == total_blocks - 1)
			{
				fwrite(sentence + 1, 1, fmin(72, 72 - (total_blocks == 1 ? extra_data : extra_data - 1)), append_file);
			}
			else
			{
				fwrite(sentence + 1, 1, 71, append_file);
			}
		}
		else if (!encrypting && block_amount == total_blocks - 1)
		{
			fwrite(sentence, 1, fmin(72, 72 - (extra_data - 1)), append_file);
		}
		else
		{
			fwrite(sentence, 1, 72, append_file);
		}
	}

	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	std::cout << std::to_string(security_level) << ": " << std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count() / total_blocks << "ns per block (Average) - " << 1.0 / ((std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count() / total_blocks) / 75000.0f) << " MB/s" << std::endl;

	//Delete Original file id flag is set
	if (argc == 6 && std::strcmp(argv[5], "-d") == 0) {
		bytes_file.close();
		remove((encrypting ? first_file : second_file).c_str());
	}
}