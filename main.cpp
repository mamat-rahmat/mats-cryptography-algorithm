#include "mats_cipher.hpp"
#include <bits/stdc++.h>
using namespace std;

int main() {
	mats_cipher cc;

	
	cout << "# TEST get_sha256() and convert_256_to_128()" << endl;
	cout << "SHA256(mamat)  : " << cc.get_sha256("mamat") << endl;
	cout << "Convert to 128 : " << cc.convert_256_to_128(cc.get_sha256("mamat")) << endl;
	cout << endl;
	

	
	cout << "# TEST single_encipher() and single_decipher()" << endl;
	string plain1 = "1234567812345678";
	string key1 = "asdfghjkasdfghjk";
	cout << "plain : " << plain1 << endl;
	cout << "key   : " << key1 << endl;
	string enc1 = cc.single_encipher(plain1,key1);
	cout << "encrypted  : " << enc1 << endl;
	string dec1 = cc.single_decipher(enc1,key1);
	cout << "decrypted : " << dec1 << endl;
	cout << endl;
	

	
	cout << "# TEST sub_bytes()" << endl;
	string plain2 = "abcdefghijklmnopqrstuvwxyz";
	cout << "plain : " << plain2 << endl;
	string enc2 = cc.sub_bytes(plain2, true);
	cout << "encrypted  : " << enc2 << endl;
	string dec2 = cc.sub_bytes(enc2, false);
	cout << "decrypted : " << dec2 << endl;
	cout << endl;
	

	
	cout << "# TEST do_encipher() and do_decipher()" << endl;
	// ECB mode if two of them are false
	cc.isCBC = false;
	cc.isCFB = false;
	string plain = "Lorem ipsum dolor sit amet, nam rebum fugit alterum eu. Id vidit delenit urbanitas vis, regione electram pri ex, dicam consul causae sit te. Stet semper mel ei. Velit debet imperdiet qui an, cu oratio omnium sanctus nec. Vim solet nonumy labore ea, assum invidunt recusabo ea has. Veritus necessitatibus vis at, sed ex esse duis. Mei ne rebum erant luptatum, altera volutpat molestiae sea et. Te pri alii blandit perfecto. Quo at ridens periculis, in numquam dolorem qui. Qui cu mundi vivendo sapientem. Cum doctus apeirian accusamus cu, usu ei civibus apeirian. Posse ridens vix id. Ius ne explicari reprehendunt, cu pri inani ornatus, tation theophrastus ne eam. Ea nec quis justo, cu habeo timeam debitis vim. Has eu eirmod antiopam concludaturque, in probo dolore mnesarchum quo, per impedit nominavi no. Partem aperiri gloriatur est in. Usu nostro postulant at. Populo civibus albucius nec id, pro congue eruditi explicari ne, duo et velit scripserit ullamcorper. Duo at purto platonem, pro ex solet tation appareat. Tale sale ut qui. His in soleat posidonium. Ea sea aeque euripidis, eum ad nihil omnesque salutandi. Nisl commune accumsan ad eos. Tibique mediocrem vituperatoribus nec ex, usu ne stet augue praesent. Veri necessitatibus ea ius, melius scribentur deterruisset nec ad. Pro no noster hendrerit.";
	//string plain = "123456789012345 123456789012345 123456789012345 123456789012345 123456789012345 123456789012345 123456789012345 ";
	string key = "mamat rahmat & ramandika pranamulia";
	cout << "plain : " << plain << endl;
	cout << "key   : " << key << endl;
	string enc = cc.do_encipher(plain,key);
	cout << "encrypted  : " << enc << endl;
	string dec = cc.do_decipher(enc,key);
	cout << "dencrypted : " << dec << endl;
	cout << endl;
	return 0;
	
}