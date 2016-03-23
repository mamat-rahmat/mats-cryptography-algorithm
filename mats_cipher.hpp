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
		string XOR (string s1, string s2);	  

		string single_encipher(string s_in, string i_key);
		string single_decipher(string s_in, string i_key);
		
		pssss do_modified_feistel(pssss p, string i_key);
		string sub_bytes(string s_in);
		string get_sha256(string s_in);
		string convert_256_to_128(string s);
	public: 
		bool isCBC, isCFB;
		mats_cipher();		
		string do_encipher(string s_in, string g_key);
		string do_decipher(string s_in, string g_key);
};

