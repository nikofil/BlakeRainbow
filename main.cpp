#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <functional>
#include <unordered_map>
#include <set>
#include <memory>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include "blake.h"

#define CHAINLEN 2000
//#define CHAINLEN 3

/* turn a 6 character string into a 64-bit unsigned int */
#define CHARTOLONG(c) \
	((uint64_t)c[0]) | ((uint64_t)c[1] << 8) | ((uint64_t)c[2] << 16) | \
	((uint64_t)c[3] << 24) | ((uint64_t)c[4] << 32) | ((uint64_t)c[5] << 40)

using namespace std;

static const char *letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@";

/* reduce a hash to another string */
void next(uint8_t *out, char *str, uint8_t rind[], bool cont = false) {
	/*
	* rind says which bytes will be xored together to make the index for the next letter
	* we need 6 such indexes so rind is an array of 7 ints
	* for the n-th index we xor the bytes [rind[n], rind[n+1])
	* and bitwise-AND the result with 63 to get an index in [0, 63]
	* then use that index to get the new n-th letter of the next str
	*/
	for (int i = 0; i < 6; i++) {
		uint32_t x = 0;
		for (int j = rind[i]; j < rind[i + 1]; j++)
			x ^= out[j];
		str[i] = letters[x & 63];
	}
	/*
	* If cont is true we increase the rind meaning we increase rind[5]
	* (the last index besides rind[6] which is always 32, the last byte)
	* and make sure it's not more than 31, in which case we increase rind[4]
	* and make rind[5] = rind[4] + 1.
	* We also make sure rind[4] is not more than 30 and repeat this process
	* if it is (hence rind[i] - i == 27)
	*/
	if (cont) {
		int i = 5;
		rind[5]++;
		while (rind[i] - i == 27 && i > 0)
			rind[--i]++;
		for (int j = i; j < 5; j++)
			rind[j + 1] = rind[j] + 1;
	}
}

/* make chain starting from a string and write to out */
void dochain(char *startstr, ofstream &out) {
	uint8_t hash[32], rind[7] = {0, 1, 2, 3, 4, 5, 32};
	char str[7];
	strcpy(str, startstr);
	/* save the start of the chain */
	out << str;
	for (int i = 0; i < CHAINLEN; i++) {
		/* advance CHAINLEN times in the chain */
		blake256_hash(hash, reinterpret_cast<uint8_t*>(str), 6);
		next(hash, str, rind, true);
	}
	/* save the end of the chain */
	out << str;
	out << endl;
}

/* make chains starting from specific letters */
void makechains(const char *startstr) {
	string ofname("0test.rbw");
	ofname[0] = startstr[0];
	ofstream out(ofname);
	char str[7];
	strcpy(str, startstr);
	/* loop through letters to make strings to start chains */
	/* only the last 4 letters of startstr will be changed */
	for (int i = 0; i < 10; i++) {
		cout << "i loop " << i << endl;
		str[2] = letters[i];
		for (int j = 0; letters[j] != '\0'; j++) {
			cout << "j loop " << j << endl;
			str[3] = letters[j];
			for (int k = 0; letters[k] != '\0'; k++) {
				str[4] = letters[k];
				for (int l = 0; letters[l] != '\0'; l++) {
					str[5] = letters[l];
					/* make chain starting with str and save in out */
					dochain(str, out);
				}
			}
		}
	}
	cout << "Done" << endl;
}

void lookforsol(const vector< unique_ptr<uint8_t[]> > &hashparams,
	const unordered_map<uint64_t, set<uint64_t> > &endtostart, int from, int to, uint8_t bytes[]) {
	for (int hashstart = from; hashstart < to; hashstart++) {
		uint8_t hash[32];
		char str[7];
		str[6] = '\0';
		memcpy(hash, bytes, 32);
		int curhash = hashstart;
		/* use all rinds from hashparams[hashstart] to hashparams[hashparams.size() - 1] */
		while (curhash < hashparams.size()) {
			next(hash, str, hashparams[curhash].get());
			blake256_hash(hash, reinterpret_cast<uint8_t*>(str), 6);
			curhash++;
		}
		/* if we have found a chain end */
		if (endtostart.count(CHARTOLONG(str)) != 0) {
			// cout << "Found! " << str << endl;
			for (uint64_t uintstart : endtostart.at(CHARTOLONG(str))) {
				str[0] = (char)(uintstart & 0xFF);
				str[1] = (char)((uintstart >> 8) & 0xFF);
				str[2] = (char)((uintstart >> 16) & 0xFF);
				str[3] = (char)((uintstart >> 24) & 0xFF);
				str[4] = (char)((uintstart >> 32) & 0xFF);
				str[5] = (char)((uintstart >> 40) & 0xFF);
				/* get the chain start */
				for (auto hashiter = hashparams.cbegin(); hashiter != hashparams.cend(); hashiter++) {
					/* follow the chain */
					blake256_hash(hash, reinterpret_cast<uint8_t*>(str), 6);
					if (memcmp(bytes, hash, 32) == 0) {
						/* found a match with the hash */
						int pipes[2];
						cout << "Found plaintext: " << str << endl;
						pipe(pipes);
						/* telnet to the service and write the password */
						if (fork() == 0) {
							dup2(pipes[0], 0);
							execl("/usr/bin/telnet", "/usr/bin/telnet", "localhost", "4433", NULL);
							// execl("/usr/bin/rev", "/usr/bin/rev", NULL);
						} else {
							char nl = '\n';
							write(pipes[1], str, 6);
							write(pipes[1], &nl, 1);
						}
						break;
					}
					next(hash, str, (*hashiter).get());
				}
			}
		}
	}
}

/* utilize the generated rainbow tables to answer queries about hashes */
void waitforhash() {
	vector< unique_ptr<uint8_t[]> > hashparams;
	uint8_t cur[7] = {0, 1, 2, 3, 4, 5, 32};
	for (int i = 0; i < CHAINLEN; i++) {
		/* save each possible rind used in the 'next' function to make any chain */
		unique_ptr<uint8_t[]> nextparam(new uint8_t[7]);
		for (int j = 0; j < 7; j++)
			nextparam.get()[j] = cur[j];
		/* copy and save cur */
		hashparams.push_back(move(nextparam));
		/* advance cur */
		cur[5]++;
		int j = 5;
		while (cur[j] - j == 27 && j > 0)
			cur[--j]++;
		for (int k = j; k < 5; k++)
			cur[k + 1] = cur[k] + 1;
	}
	unordered_map<uint64_t, set<uint64_t> > endtostart;
	string fname = "0.rbw";
	try {
		for (char i = 'A'; i <= 'H'; i++) {
			/* load each file */
			fname[0] = i;
			ifstream hashfile(fname);
			if (!hashfile.is_open()) {
				cout << "File " << fname << " not found" << endl;
				return;
			}
			string s;
			getline(hashfile, s);
			while (!hashfile.eof()) {
				/* map of each chain end to all chain starts that end that way */
				endtostart[CHARTOLONG(s.substr(6, 6).c_str())].insert(CHARTOLONG(s.substr(0, 6).c_str()));
				getline(hashfile, s);
			}
			cout << "Loaded " << fname << endl;
		}
	} catch (exception e) {
		/* sometimes this runs out of memory */
		cerr << "Error: " << e.what() << endl;
		return;
	}
	cout << "Waiting for hash..." << endl;
	string bytestring;
	cin >> bytestring;
	while (bytestring.length() == 64) {
		cout << "Got hash: " << bytestring << endl;
		uint8_t bytes[32];
		/* change from string to uint8_t array */
		for (int i = 0; i < 32; i++)
			bytes[i] = static_cast<char>(stol(bytestring.substr(i * 2, 2), 0, 16));
		/* try to divide work equally between two threads (starting a chain earlier is more
		   expensive as it has to go through more reductions) */
		thread thr(lookforsol, cref(hashparams), cref(endtostart), 0, CHAINLEN*6/20, bytes);
		lookforsol(hashparams, endtostart, CHAINLEN*6/20, CHAINLEN, bytes);
		thr.join();
		cout << "Waiting for hash..." << endl;
		cin >> bytestring;
	}
	cout << "Exiting..." << endl;
}

/* make rainbow tables using 8 threads */
void gentables() {
	vector<thread> vt;
	/* first chain starts from "AAAAAA", second from "BBBBBB" etc. */
	vt.push_back(thread(makechains, "AAAAAA"));
	vt.push_back(thread(makechains, "BBBBBB"));
	vt.push_back(thread(makechains, "CCCCCC"));
	vt.push_back(thread(makechains, "DDDDDD"));
	vt.push_back(thread(makechains, "EEEEEE"));
	vt.push_back(thread(makechains, "FFFFFF"));
	vt.push_back(thread(makechains, "GGGGGG"));
	makechains("HHHHHH");
	for (auto &t : vt)
		t.join();
}

int main(int argc, char *argv[]) {
	// gentables(); /* generate the rainbow tables */
	waitforhash(); /* crack hashes */
	return 0;
}
