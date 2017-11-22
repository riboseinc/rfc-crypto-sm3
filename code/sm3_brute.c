/*
 * gcc -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto sm3_brute.c -o sm3_brute && ./sm3_brute
 */
#include <openssl/bn.h>

/*
   The elliptic curve equation is:
   y^2 + xy = x^3 + ax^2 + b
*/

int main(void)
{
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	BIGNUM* xb = BN_new();
	BIGNUM* yb = BN_new();
	BIGNUM* xa = BN_new();
	BIGNUM* ya = BN_new();
	BIGNUM* xg = BN_new();
	BIGNUM* yg = BN_new();
	BIGNUM* tmp = BN_new();

	BN_hex2bn(&a,  "0");
	BN_hex2bn(&b,  "00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B");
	BN_hex2bn(&xg, "00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD");
	BN_hex2bn(&yg, "013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E");
	BN_hex2bn(&xa, "008E3BDB2E11F9193388F1F901CCC857BF49CFC065FB38B9069CAAE6D5AFC3592F");
	BN_hex2bn(&ya, "004555122AAC0075F42E0A8BBD2C0665C789120DF19D77B4E3EE4712F598040415");

	BN_hex2bn(&xb, "00A67941E6DE8A61805F7BCFF0985BB3BED986F1C297E4D8880D82B821C624EE57");
	BN_hex2bn(&yb, "0193ED5A6707B5908781B860841085F52EEFA7FE329A5C811843533A874D027271");

	//degree n: 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D

	// for all x, we fix y
	/* // real
	BIGNUM* fixed_y = BN_dup(ya);
	BIGNUM* tmp_x = BN_dup(xa);
	*/
	BIGNUM* fixed_y = BN_dup(yb);
	BIGNUM* tmp_x = BN_dup(xb);
	// TODO Set value X_A changes

	BIGNUM* number_2 = BN_new();
	BIGNUM* number_3 = BN_new();
	BIGNUM* number_256 = BN_new();

	BIGNUM* y_2 = BN_new();
	BIGNUM* xy = BN_new();
	BIGNUM* left = BN_new();

	printf("INPUTS: \n");
	printf("- a %s\n", BN_bn2hex(a));
	printf("- b %s\n", BN_bn2hex(b));
	printf("- x %s\n", BN_bn2hex(tmp_x));
	printf("- y %s\n", BN_bn2hex(fixed_y));

	printf("\nCALCULATION: \n");
	/*
	BN_mod_exp(y_2, fixed_y, number_2, number_256, ctx);
	printf("BN_bn2hex y^2 %s\n", BN_bn2hex(y_2));
	BN_mod_mul(xy, fixed_y, tmp_x, number_256, ctx);
	BN_mod_add(left, y_2, xy, number_256, ctx);
	*/
	//BN_exp(y_2, fixed_y, number_2, ctx);
	BN_mul(y_2, fixed_y, fixed_y, ctx);
	printf("- y^2 %s\n", BN_bn2hex(y_2));
	BN_mul(xy, fixed_y, tmp_x, ctx);
	printf("- xy %s\n", BN_bn2hex(xy));
	BN_add(left, y_2, xy);
	printf("=> y^2 + xy = %s\n", BN_bn2hex(left));

	BIGNUM* x_3 = BN_new();
	BIGNUM* x_2 = BN_new();
	BIGNUM* ax2 = BN_new();
	BIGNUM* right = BN_new();

	/*
	BN_mod_exp(x_3, tmp_x, number_3, number_256, ctx);
	BN_mod_mul(ax2, a, tmp_x, number_256, ctx);
	BN_mod_add(right, x_3, ax, number_256, ctx);
	BN_mod_add(right, right, b, number_256, ctx);
	*/

	printf("\nCALCULATION: \n");
	//BN_exp(x_3, tmp_x, number_3, ctx);
	//BN_exp(x_2, tmp_x, number_2, ctx);
	BN_mul(x_2, tmp_x, tmp_x, ctx);
	BN_mul(x_3, x_2, tmp_x, ctx);
	BN_mul(ax2, a, x_2, ctx);
	BN_add(right, x_3, ax2);
	BN_add(right, right, b);
	printf("- x^3 = %s\n", BN_bn2hex(x_3));
	printf("- x^2 = %s\n", BN_bn2hex(x_2));
	printf("- ax^2 = %s\n", BN_bn2hex(ax2));
	printf("- b = %s\n", BN_bn2hex(b));
	printf("=> x^3 + ax^2 + b = %s\n", BN_bn2hex(right));

	BIGNUM* minus = BN_new();
	BN_sub(minus, right, left);
	printf("right - left = %s\n", BN_bn2hex(minus));

	int result = BN_cmp(left, right);

	BN_free(a);
	BN_free(b);
	BN_free(xa);
	BN_free(ya);
	BN_free(xg);
	BN_free(yg);

	printf("result = %d\n", result);
	return 0;
}
