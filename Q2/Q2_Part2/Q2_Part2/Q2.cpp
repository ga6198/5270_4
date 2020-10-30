// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "des.h"
using CryptoPP::DES;

#include "modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "hrtimer.h";

#include "nbtheory.h";

#include "rsa.h";
#include "rsa.cpp";
#include <fstream>;

#include <files.h>;

#include <filters.h>;

#include "sha.h";
using CryptoPP::SHA1;

#include "ripemd.h";
using CryptoPP::RIPEMD160;

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <md5.h>
using CryptoPP::Weak::MD5;

#include <stdlib.h>;
#include <time.h>;

#include <vector>;

// function to convert hex to binary
// Source: https://www.geeksforgeeks.org/program-to-convert-hexadecimal-number-to-binary/
string hexToBin(string hexdec)
{
    long int i = 0;

    string bin_string = "";

    while (hexdec[i]) {

        switch (hexdec[i]) {
        case '0':
            bin_string += "0000";
            break;
        case '1':
            bin_string += "0001";
            break;
        case '2':
            bin_string += "0010";
            break;
        case '3':
            bin_string += "0011";
            break;
        case '4':
            bin_string += "0100";
            break;
        case '5':
            bin_string += "0101";
            break;
        case '6':
            bin_string += "0110";
            break;
        case '7':
            bin_string += "0111";
            break;
        case '8':
            bin_string += "1000";
            break;
        case '9':
            bin_string += "1001";
            break;
        case 'A':
        case 'a':
            bin_string += "1010";
            break;
        case 'B':
        case 'b':
            bin_string += "1011";
            break;
        case 'C':
        case 'c':
            bin_string += "1100";
            break;
        case 'D':
        case 'd':
            bin_string += "1101";
            break;
        case 'E':
        case 'e':
            bin_string += "1110";
            break;
        case 'F':
        case 'f':
            bin_string += "1111";
            break;
        default:
            cout << "\nInvalid hexadecimal digit "
                << hexdec[i];
        }
        i++;
    }

    return bin_string;
}

string shaHash(int block_size, string plaintext) {
	string digest;
	SHA1 hash;
    string hash_destination;
	//HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    HexEncoder encoder(new CryptoPP::StringSink(hash_destination));

	StringSource(plaintext, true, new CryptoPP::HashFilter(hash, new StringSink(digest)));

	//Send digest to hash_destination
	StringSource(digest, true, new CryptoPP::Redirector(encoder));

    //cout << hash_destination << endl;

    //Convert hexadecimal to binary
    string bin_digest = hexToBin(hash_destination);
    //cout << bin_digest << endl;

	return bin_digest;
}

string ripeHash(int block_size, string plaintext) {
    string digest;
    RIPEMD160 hash;
    string hash_destination;
    //HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    HexEncoder encoder(new CryptoPP::StringSink(hash_destination));

    StringSource(plaintext, true, new CryptoPP::HashFilter(hash, new StringSink(digest)));

    //Send digest to hash_destination
    StringSource(digest, true, new CryptoPP::Redirector(encoder));

    //cout << hash_destination << endl;

    //Convert hexadecimal to binary
    string bin_digest = hexToBin(hash_destination);
    //cout << bin_digest << endl;

    return bin_digest;
}

string mdHash(int block_size, string plaintext) {
    string digest;
    MD5 hash;
    string hash_destination;
    //HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    HexEncoder encoder(new CryptoPP::StringSink(hash_destination));

    StringSource(plaintext, true, new CryptoPP::HashFilter(hash, new StringSink(digest)));

    //Send digest to hash_destination
    StringSource(digest, true, new CryptoPP::Redirector(encoder));

    //cout << hash_destination << endl;

    //Convert hexadecimal to binary
    string bin_digest = hexToBin(hash_destination);
    //cout << bin_digest << endl;

    return bin_digest;
}

//find number of changed bits and locations for two binary hashes of equal length
void findDifference(string hash1, string hash2) {
    int changed_bits = 0;
    std::vector<int> positions = {};

    for (int i = 0; i < hash1.length(); i++) {
        //if the current characters don't match in the strings, raise the counter
        if (hash1[i] != hash2[i]) {
            changed_bits += 1;
            positions.push_back(i);
        }
    }

    cout << "Number of different bits: " << changed_bits << endl;
    cout << "Index of changed bits: ";
    for (int n : positions) {
        cout << n << " ";
    }

    cout << endl << endl;
}

int main(int argc, char* argv[])
{
	//Initialize random seed
	srand(time(NULL));

	//Load the plaintext for both encryptions and decryptions
	string plaintext = "";
	std::ifstream myfile("plain_kb.txt");
	if (myfile.is_open()) {
		string line;
		while (getline(myfile, line)) {
			plaintext += line;
		}

		myfile.close();
	}
	//cout << plaintext << endl;

	//first byte changed
	string plaintext_first = plaintext.substr(0).replace(0, 1, "a");

	//last byte changed
	string plaintext_last = plaintext.substr(0).replace(plaintext.length() - 1, 1, "a");

	//random byte changed
	int rand_pos = rand() % plaintext.length();
	string plaintext_random = plaintext.substr(0).replace(rand_pos, 1, "a");

	cout << "Original plaintext" << endl;
	cout << plaintext << endl << endl;
	cout << "First byte modified" << endl;
	cout << plaintext_first << endl << endl;
	cout << "Last byte modified" << endl;
	cout << plaintext_last << endl << endl;
	cout << "Random byte modified" << endl;
	cout << plaintext_random << endl << endl;

    //SHA-1
    string sha_original = shaHash(512, plaintext);
    string sha_first = shaHash(512, plaintext_first);
    string sha_last = shaHash(512, plaintext_last);
    string sha_random = shaHash(512, plaintext_random);
    cout << "------------------------------------------" << endl;
	cout << "SHA-1" << endl;
    cout << "With original plaintext" << endl;
	cout << sha_original << endl;
    cout << "With modified plaintext first byte" << endl;
    cout << sha_first << endl;
    findDifference(sha_original, sha_first);
    cout << "With modified plaintext last byte" << endl;
    cout << sha_last << endl;
    findDifference(sha_original, sha_last);
    cout << "With modified plaintext random byte" << endl;
    cout << sha_random << endl;
    findDifference(sha_original, sha_random);
    cout << "------------------------------------------" << endl;
    cout << endl;

    //RIPEMD160
    string ripe_original = ripeHash(512, plaintext);
    string ripe_first = ripeHash(512, plaintext_first);
    string ripe_last = ripeHash(512, plaintext_last);
    string ripe_random = ripeHash(512, plaintext_random);
    cout << "------------------------------------------" << endl;
    cout << "RIPEMD160" << endl;
    cout << "With original plaintext" << endl;
    cout << ripe_original << endl;
    cout << "With modified plaintext first byte" << endl;
    cout << ripe_first << endl;
    findDifference(ripe_original, ripe_first);
    cout << "With modified plaintext last byte" << endl;
    cout << ripe_last << endl;
    findDifference(ripe_original, ripe_last);
    cout << "With modified plaintext random byte" << endl;
    cout << ripe_random << endl;
    findDifference(ripe_original, ripe_random);
    cout << "------------------------------------------" << endl;
    cout << endl;

    //MD5
    string md_original = mdHash(512, plaintext);
    string md_first = mdHash(512, plaintext_first);
    string md_last = mdHash(512, plaintext_last);
    string md_random = mdHash(512, plaintext_random);
    cout << "------------------------------------------" << endl;
    cout << "MD5" << endl;
    cout << "With original plaintext" << endl;
    cout << md_original << endl;
    cout << "With modified plaintext first byte" << endl;
    cout << md_first << endl;
    findDifference(md_original, md_first);
    cout << "With modified plaintext last byte" << endl;
    cout << md_last << endl;
    findDifference(md_original, md_last);
    cout << "With modified plaintext random byte" << endl;
    cout << md_random << endl;
    findDifference(md_original, md_random);
    cout << "------------------------------------------" << endl;
    cout << endl;

	return 0;
}

