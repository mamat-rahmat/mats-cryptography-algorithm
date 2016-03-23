#pragma once

#include <bits/stdc++.h>
#include "sha256.h"
using namespace std;

#define left first
#define right second
#define up first
#define down second
typedef pair<pair<string,string>,pair<string, string> > pssss;
typedef pair<string,string> pss;

class mats_cipher{
	private:
		vector<string> s_blocks;
		static const unsigned char s_box[256];
		static const unsigned char s_box_reverse[256];

	public: 
		bool isCBC, isCFB;
		mats_cipher();		
		
		string XOR (string s1, string s2);
		char XOR(char c1, char c2);

		string single_encipher(string s, string key);
		string single_decipher(string s, string key);
		
		string do_modified_feistel(string p, string key, bool encrypt);
		string sub_bytes(string s, bool encrypt);
		string get_sha256(string s);
		string convert_256_to_128(string s);

		string do_encipher(string s, string key);
		string do_decipher(string s, string key);
};

