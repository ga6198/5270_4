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

void printThroughput(double total_time, double total_bytes) {
	cout << "Time: " << total_time << " seconds" << endl;
	double throughput = total_bytes / total_time;
	cout << "Throughput: " << throughput << " bytes per second" << endl;
	cout << endl;
}

void shaHash(int block_size, string plaintext) {
	string digest;
	SHA1 hash;
	HexEncoder encoder(new CryptoPP::FileSink(std::cout));

	CryptoPP::ThreadUserTimer timer;
	timer.StartTimer();

	StringSource(plaintext, true, new CryptoPP::HashFilter(hash, new StringSink(digest)));
	
	//Print digest
	StringSource(digest, true, new CryptoPP::Redirector(encoder));
	cout << endl;
	
	double total_bytes = 1048576;

	/*
	string whole_hash = "";
	cout << "Hashing..." << endl;
	for (int i = 0; i < total_bytes; i = i + block_size) {
		string current_plain = plaintext.substr(i, block_size);
		//cout << current_plain << endl;

		string current_digest;
		try {
			StringSource(current_plain, true, new CryptoPP::HashFilter(hash, new StringSink(current_digest)));
			whole_hash += current_digest;
			StringSource(current_digest, true, new CryptoPP::Redirector(encoder));
			cout << endl;
		}
		catch (CryptoPP::Exception & e) {
			cout << e.what() << endl;
		}
	}
	//Print digest
	cout << "Whole hash" << endl;
	StringSource(whole_hash, true, new CryptoPP::Redirector(encoder));
	*/
	double total_time = timer.ElapsedTimeAsDouble();
	printThroughput(total_time, total_bytes);
}

void ripeHash(int block_size, string plaintext) {
	string digest;
	RIPEMD160 hash;
	HexEncoder encoder(new CryptoPP::FileSink(std::cout));

	CryptoPP::ThreadUserTimer timer;
	timer.StartTimer();

	StringSource(plaintext, true, new CryptoPP::HashFilter(hash, new StringSink(digest)));

	//Print digest
	StringSource(digest, true, new CryptoPP::Redirector(encoder));
	cout << endl;

	double total_bytes = 1048576;

	/*
	string whole_hash = "";
	cout << "Hashing..." << endl;
	for (int i = 0; i < total_bytes; i = i + block_size) {
		string current_plain = plaintext.substr(i, block_size);
		//cout << current_plain << endl;

		string current_digest;
		try {
			StringSource(current_plain, true, new CryptoPP::HashFilter(hash, new StringSink(current_digest)));
			whole_hash += current_digest;
			StringSource(current_digest, true, new CryptoPP::Redirector(encoder));
			cout << endl;
		}
		catch (CryptoPP::Exception & e) {
			cout << e.what() << endl;
		}
	}
	//Print digest
	cout << "Whole hash" << endl;
	StringSource(whole_hash, true, new CryptoPP::Redirector(encoder));
	*/
	double total_time = timer.ElapsedTimeAsDouble();
	printThroughput(total_time, total_bytes);
}

void mdHash(int block_size, string plaintext) {
	string digest;
	MD5 hash;
	HexEncoder encoder(new CryptoPP::FileSink(std::cout));

	CryptoPP::ThreadUserTimer timer;
	timer.StartTimer();

	StringSource(plaintext, true, new CryptoPP::HashFilter(hash, new StringSink(digest)));

	//Print digest
	StringSource(digest, true, new CryptoPP::Redirector(encoder));
	cout << endl;

	double total_bytes = 1048576;

	/*
	string whole_hash = "";
	cout << "Hashing..." << endl;
	for (int i = 0; i < total_bytes; i = i + block_size) {
		string current_plain = plaintext.substr(i, block_size);
		//cout << current_plain << endl;

		string current_digest;
		try {
			StringSource(current_plain, true, new CryptoPP::HashFilter(hash, new StringSink(current_digest)));
			whole_hash += current_digest;
			StringSource(current_digest, true, new CryptoPP::Redirector(encoder));
			cout << endl;
		}
		catch (CryptoPP::Exception & e) {
			cout << e.what() << endl;
		}
	}
	//Print digest
	cout << "Whole hash" << endl;
	StringSource(whole_hash, true, new CryptoPP::Redirector(encoder));
	*/
	double total_time = timer.ElapsedTimeAsDouble();
	printThroughput(total_time, total_bytes);
}

int main(int argc, char* argv[])
{
	//Load the plaintext for both encryptions and decryptions
	string plaintext = "";
	std::ifstream myfile("plain.txt");
	if (myfile.is_open()) {
		string line;
		while (getline(myfile, line)) {
			plaintext += line;
		}

		myfile.close();
	}
	//cout << plaintext << endl;

	cout << "SHA-1" << endl;
	shaHash(512, plaintext);

	cout << "RIPEMD160" << endl;
	ripeHash(512, plaintext);

	cout << "MD5" << endl;
	mdHash(512, plaintext);
	//hash(1024, 5, plaintext); //86 keylength
	
	return 0;
}

