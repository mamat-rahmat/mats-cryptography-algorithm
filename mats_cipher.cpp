#include "mats_cipher.hpp"

const unsigned char mats_cipher::s_box[256] = {
		   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
		};

mats_cipher::mats_cipher() {}
		
string mats_cipher::XOR(string s1, string s2) {
	string ans="";
	assert(s1.size()==s2.size());
	for(int i=0; i<s1.size(); i++) {
		char c = s1[i]^s2[i];
		ans += c;
	}
	return ans;
}

char mats_cipher::XOR(char c1, char c2) {
	char ans = c1^c2;
	return ans;
}

string mats_cipher::single_encipher(string s, string key) {
	assert(s.size() == 16);

	string round_key = convert_256_to_128(get_sha256(key));
	string out = s;

	//do the modified feistel round 16 times
	for(int i=0; i<16; i++) {
        cout << out.size() << " " << round_key.size() << endl;
		assert(out.size() == round_key.size());
		out = do_modified_feistel(out, round_key);
		round_key = convert_256_to_128(get_sha256(round_key));
	}
	string result = out;
	return result;
}

string mats_cipher::single_decipher(string s, string key) {
	assert(s.size() == 16);

	string round_key = convert_256_to_128(get_sha256(key));
	string out = s;

	//do the modified feistel round 16 times
	for(int i=0; i<16; i++) {
		assert(out.size() == round_key.size());
		out = do_modified_feistel(out, round_key);
		round_key = convert_256_to_128(get_sha256(round_key));
	}
	string result = out;
	return result;
}


string mats_cipher::do_encipher(string s, string key) {
	s_blocks.clear(); //clear blocks of string
	
	//partitioning s into s_blocks
	string temp="";
	for(int i=0; i<s.size(); i++) {
		if(i%16==0) {
			if(i>0) s_blocks.push_back(temp);
			temp = "";
		}
		temp += s[i];
	}
	if(temp!="") { //handling last string, padding zeroes in the back until length = 32 
		string last_s = temp;
		int remainder = 16 - last_s.size();
		for(int i=0; i<remainder; i++) last_s += (char)0;
		s_blocks.push_back(last_s);
	}
	
	//get round1 key
	string round_key = convert_256_to_128(get_sha256(key));
	string ans="";
	
	if (isCBC) {
		//create initialization vector from key
		string init_v = convert_256_to_128(get_sha256(key));

		for(int i=0; i<s_blocks.size(); i++) { //do encryption
			string result = XOR(init_v,s_blocks[i]);
			init_v = single_encipher(result, round_key);
			ans += init_v;
		}
	}
	else if (isCFB) {
		//create initialization vector from key
		string init_v = convert_256_to_128(get_sha256(key));
		
		for(int i=0; i<s_blocks.size()*16; i++) { //do encryption
			string MSC = "" + single_encipher(init_v, round_key).substr(0,1);
			string plainchar = "" + s_blocks[i/16].substr(i%16,1);
			string result = XOR(MSC,plainchar);
			ans += result;
			init_v = init_v.substr(1) + result;
		}
	}
	else	//encipher each block, it is ECB mode
	for(int i=0; i<s_blocks.size(); i++) {
		string s_b = single_encipher(s_blocks[i], round_key);
		ans += s_b;
	}
	return ans;
}

// TODO
string mats_cipher::do_decipher(string s, string key) {
	s_blocks.clear(); //clear blocks of string
	//partitioning s_in into s_blocks
	string temp="";
	for(int i=0; i<s.size(); i++) {
		if(i%16==0) {
			if(i>0) s_blocks.push_back(temp);
			temp = "";
		}
		temp += s[i];
	}
	if(temp!="") { //handling last string, padding zeroes in the back until length = 32 
		string last_s = temp;
		int remainder = 16 - last_s.size();
		for(int i=0; i<remainder; i++) last_s += (char)0;
		s_blocks.push_back(last_s);
	}
	
	//get round1 key
	string round_key = convert_256_to_128(get_sha256(key));
	string ans="";
	
	if (isCBC) {
		//create initialization vector from g_key
		string init_v = convert_256_to_128(get_sha256(key));
		
		for(int i=0; i<s_blocks.size(); i++) { //do encryption
			string dec = single_decipher(s_blocks[i], round_key);
			string result = XOR(dec,init_v);
			ans += result;
			init_v = s_blocks[i];
		}
	}
	else if(isCFB) {
		string init_v = convert_256_to_128(get_sha256(key));
		
		for(int i=0; i<s_blocks.size()*16; i++) { //do encryption
			string MSC = "" + single_encipher(init_v, round_key).substr(0,1);
			string cipherchar = "" + s_blocks[i/16].substr(i%16,1);
			string result = XOR(MSC,cipherchar);
			ans += result;
			init_v = init_v.substr(1) + cipherchar;
		}
	}
	else	//encipher each block, it is ECB mode
	for(int i=0; i<s_blocks.size(); i++) {
		string s_b = single_decipher(s_blocks[i], round_key);
		ans += s_b;
	}
	return ans;
}


string mats_cipher::do_modified_feistel(string s, string key) {
	assert(key.size() == 16);
	assert(s.size() == 16);

	//substitute bytes
	//s = sub_bytes(s);
	
	// create box of string 2x2 to make implementation easier
	string atas = s.substr(0, s.length()/2);
	string atas_kiri = atas.substr(0, atas.length()/2);
	string atas_kanan = atas.substr(atas.length()/2);
	string bawah = s.substr(s.length()/2);
	string bawah_kiri = bawah.substr(0, bawah.length()/2);
	string bawah_kanan = bawah.substr(bawah.length()/2);
	string sbox[4] = {atas_kiri, atas_kanan, bawah_kiri, bawah_kanan};
	
	// find 2 from 4 index between {0, 1, 2, 3} that will be encrypted
	vector<pair<int,int> > tot;
	for(int i=0; i<4; i++)
		tot.push_back(make_pair(0, i));

	for(int i=0; i<16; i++) {
		int bil1 = int(key[i]) & 0XF;
		int bil2 = int(key[i] >> 4) & 0XF;
		tot[(bil1+bil2)%4].first++;
	}

	// urutkan berdasarkan "banyak"nya (first) ascending
	// jika sama, urutkan dengan index (second) lebih kecil di depan
	// jadi ambil tot[3].second sama tot[2].second (alias 2 paling belakang)
	sort(tot.begin(), tot.end());
	int choose[2] = {tot[3].second, tot[2].second};

	// enkrip 2 blok terpilih dengan orientasi dari key
	for(int i=0; i<16; i++) {
		int j=i;

		int tot=key[j];
		while(j-4>=0) {
			j -= 4;
			tot += key[j];
		}

		int nomor = tot%8;
		int idx_blok = tot/4;
		int idx_char = tot%4;
		
		sbox[choose[idx_blok]][idx_char] = XOR(key[i], sbox[choose[idx_blok]][idx_char]);
	}

	string res = sbox[0] + sbox[1] + sbox[2] + sbox[3];
	return res;
}

string mats_cipher::sub_bytes(string s) {
	string res = "";
	for (int i = 0; i < s.size(); i++) res+=s_box[s[i]];
	return res;
}

string mats_cipher::get_sha256(string s) {
	string res = sha256(s);
	return res;
}

string mats_cipher::convert_256_to_128(string s) {
	//cut key into two halves, then XOR them to get 128-bit key
	string left = s.substr(0,s.length()/2);
	string right = s.substr(s.length()/2);
	string res = XOR(left,right);
	return res;
}