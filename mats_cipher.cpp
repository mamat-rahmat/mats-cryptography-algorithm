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

string mats_cipher::single_encipher(string s_in, string i_key) {
	string r_key = i_key;

	// divide into 2x2 part
	//   _ _
	//u |_|_|
	//d |_|_|
	//   l r

	string u_in = s_in.substr(0, s_in.length()/2);	 // up part
	string u_l_in = u_in.substr(0, s_in.length()/2);   // up-left part
	string u_r_in = u_in.substr(s_in.length()/2);	  // up-right part
	
	string d_in = s_in.substr(s_in.length()/2);		// down part
	string d_l_in = u_in.substr(0, s_in.length()/2);   // down-left part
	string d_r_in = u_in.substr(s_in.length()/2);	  // down-right part
	
	// pss is pair<string, string>
	pss p_u (u_l_in, u_r_in);
	pss p_d (d_l_in, d_r_in);
	
	// pssss is pair<pair<string, string>, pair<string, string>>
	pssss p_in (p_u, p_d);
	pssss p_out = p_in;
	
	//do the modified feistel round 16 times
	for(int i=0; i<16; i++) { 
		p_out = do_modified_feistel(p_out, r_key);
		r_key = convert_256_to_128(get_sha256(r_key));
	}
	string ans = p_out.up.left + p_out.up.right + p_out.down.left + p_out.down.right;
	return ans;
}

string mats_cipher::single_decipher(string s_in, string i_key) { //TODO
	vector<string> r_key;
	r_key.push_back(i_key);

	// divide into 2x2 part
	string u_in = s_in.substr(0, s_in.length()/2);	 // up part
	string u_l_in = u_in.substr(0, s_in.length()/2);   // up-left part
	string u_r_in = u_in.substr(s_in.length()/2);	  // up-right part
	
	string d_in = s_in.substr(s_in.length()/2);		// down part
	string d_l_in = u_in.substr(0, s_in.length()/2);   // down-left part
	string d_r_in = u_in.substr(s_in.length()/2);	  // down-right part
	
	// pss is pair<string, string>
	pss p_u (u_l_in, u_r_in);
	pss p_d (d_l_in, d_r_in);
	
	// pssss is pair<pair<string, string>, pair<string, string>>
	pssss p_in (p_u, p_d);
	pssss p_out = p_in;
	
	//generate round key
	for(int i = 1; i < 16; i++)
		r_key.push_back(get_sha256(r_key[i-1]));

	//do the modified feistel round 16 times
	for(int i=15; i>=0; i--) { 
		p_out = do_modified_feistel(p_out, r_key[i]);
	}
	string ans = p_out.up.left + p_out.up.right + p_out.down.left + p_out.down.right;
	return ans;
}


//
// TODO BAGIAN BAWAH BELUM BERES
//

string mats_cipher::do_encipher(string s_in, string g_key) {
	s_blocks.clear(); //clear blocks of string
	
	//partitioning s_in into s_blocks
	string temp="";
	for(int i=0; i<s_in.size(); i++) {
		if(i%16==0) {
			if(i>0) s_blocks.push_back(temp);
			temp = "";
		}
		temp += s_in[i];
	}
	if(temp!="") { //handling last string, padding zeroes in the back until length = 32 
		string last_s = temp;
		int remainder = 16 - last_s.size();
		for(int i=0; i<remainder; i++) last_s += (char)0;
		s_blocks.push_back(last_s);
	}
	
	//get round1 key
	string r_key = convert_256_to_128(get_sha256(g_key));
	string ans="";
	
	if (isCBC) { //TO_TEST
		//make initialization vector dari g_key
		string init_v = convert_256_to_128(get_sha256(g_key));

		for(int i=0; i<s_blocks.size(); i++) { //do encryption
			string result = XOR(init_v,s_blocks[i]);
			init_v = single_encipher(result, r_key);
			ans += init_v;
		}
	}
	else if (isCFB) { //TO_TEST
		//make initialization vector dari g_key
		string init_v = convert_256_to_128(get_sha256(g_key));
		
		for(int i=0; i<s_blocks.size()*16; i++) { //do encryption
			string MSC = "" + single_encipher(init_v, r_key).substr(0,1);
			string plainchar = "" + s_blocks[i/16].substr(i%16,1);
			string result = XOR(MSC,plainchar);
			ans += result;
			init_v = init_v.substr(1) + result;
		}
	}
	else	//encipher each block, it is ECB mode
	for(int i=0; i<s_blocks.size(); i++) {
		string s_b = single_encipher(s_blocks[i], r_key);
		ans += s_b;
	}
	return ans;
}

string mats_cipher::do_decipher(string s_in, string g_key) {
	s_blocks.clear(); //clear blocks of string
	//partitioning s_in into s_blocks
	string temp="";
	for(int i=0; i<s_in.size(); i++) {
		if(i%16==0) {
			if(i>0) s_blocks.push_back(temp);
			temp = "";
		}
		temp += s_in[i];
	}
	if(temp!="") { //handling last string, padding zeroes in the back until length = 32 
		string last_s = temp;
		int remainder = 16 - last_s.size();
		for(int i=0; i<remainder; i++) last_s += (char)0;
		s_blocks.push_back(last_s);
	}
	
	//get round1 key
	string r_key = convert_256_to_128(get_sha256(g_key));
	string ans="";
	
	if (isCBC) {
		//make initialization vector dari g_key
		string init_v = convert_256_to_128(get_sha256(g_key));
		
		for(int i=0; i<s_blocks.size(); i++) { //do encryption
			string dec = single_decipher(s_blocks[i], r_key);
			string result = XOR(dec,init_v);
			ans += result;
			init_v = s_blocks[i];
		}
	}
	else if(isCFB) {
		string init_v = convert_256_to_128(get_sha256(g_key));
		
		for(int i=0; i<s_blocks.size()*16; i++) { //do encryption
			string MSC = "" + single_encipher(init_v, r_key).substr(0,1);
			string cipherchar = "" + s_blocks[i/16].substr(i%16,1);
			string result = XOR(MSC,cipherchar);
			ans += result;
			init_v = init_v.substr(1) + cipherchar;
		}
	}
	else	//encipher each block, it is ECB mode
	for(int i=0; i<s_blocks.size(); i++) {
		string s_b = single_decipher(s_blocks[i], r_key);
		ans += s_b;
	}
	return ans;
}
		
pssss mats_cipher::do_modified_feistel(pssss p, string i_key) {
	//substitute bytes
	//r_in = sub_bytes(r_in);
	
    string key = convert_256_to_128(i_key);

	// create string to make implementation easier
	string pbox_in[2][2] = {{p.up.right, p.up.left},
							{p.down.right, p.down.left}};
	
	// buat nyari 4 index antara {0, 1, 2, 3} yang akan diXOR
	// dengan hasil melihat hasil mod terbanyak
	// second = indexnya, first = banyaknya
	vector<pair<int,int> > tot;
	for(int i=0; i<4; i++)
		tot.push_back(make_pair(0, i));

	for(int a=0; a<2; a++) //up-down
		for(int b=0; b<2; b++) // left-right
			for(int i=0; i<4; i++) {
				int bil0 = int(pbox_in[a][b][i]) & 0XF;
				int bil1 = int(pbox_in[a][b][i] >> 4) & 0XF;
				tot[(bil0+bil1)%4].first++;
			}

	// urutkan berdasarkan "banyak"nya (first) ascending
	// jika sama urutkan dengan index (second) lebih kecil di depan
    // jadi ambil tot[3].second sama tot[2].second (2 paling belakang)
	sort(tot.begin(), tot.end());

    // enkrip pake orientasi dari key
    for(int i=0; i<16; i++) {
        // TODO        
    }

	pssss p_ans;
	return p_ans;
}

string mats_cipher::sub_bytes(string s_in) {
	string s_out = "";
	for (int i = 0; i < s_in.size(); i++) s_out+=s_box[s_in[i]];
	return s_out;
}

string mats_cipher::get_sha256(string s_in) {
	string res = sha256(s_in);
	return res;
}

string mats_cipher::convert_256_to_128(string s) {
    //cut key into two halves, then XOR them to get 128-bit key
    string l_s = s.substr(0,s.length()/2);
    string r_s = s.substr(s.length()/2);
    string key = XOR(l_s,r_s);
}