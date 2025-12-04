#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <string.h>

#define MAX_VALUE 65535
#define E_VALUE 3
#define MAX_TEXT_LENGTH 1024

// ============ RSA Key Generation Functions ============

uint32_t findD(uint16_t e, uint32_t phi)
{
	uint32_t eprev, dprev, d = 1, etemp, dtemp;
	
	eprev = phi, dprev = phi;
	while (e != 1)
	{
		etemp = e;
		dtemp = d;
		e = eprev - eprev / etemp * e;
		d = dprev - eprev / etemp * d;
		eprev = etemp;
		dprev = dtemp;
		while (d < 0)
			d += phi;
	}
	
	return d;
}

int ifprime(uint16_t n)
{
	uint16_t i;
	for (i = 2; i <= n / 2; i++)
	{
		if (n % i == 0)
			return 0;
	}
	return 1;
}

uint16_t gcd(uint16_t num1, uint32_t num2)
{
	uint16_t i, temp;
	if (num1 > num2)
	{
		temp = num1;
		num1 = num2;
		num2 = temp;
	}
	for (i = num1; i > 0; i--)
	{
		if (num1 % i == 0 && num2 % i == 0)
			return i;
	}
	return 1;
}

uint16_t getprime()
{
	uint16_t n;
	do
	{
		n = rand() % MAX_VALUE + 5;
	} while (!ifprime(n));
	return n;
}

void setprimes(uint16_t e, uint16_t *p, uint16_t *q, uint32_t *n, uint32_t *phi)
{
	do
	{
		*p = getprime();
		do
			*q = getprime();
		while(*p == *q);
		
		*n = *p * *q;
		*phi = *n - *p - *q + 1;
	} while (gcd(e, *phi) != 1);
}

// ============ Encryption Functions ============

unsigned long long int modpow_encrypt(int base, int power, int mod)
{
	int i;
	unsigned long long int result = 1;
	for (i = 0; i < power; i++)
	{
		result = (result * base) % mod;
	}
	return result;
}

void encrypt_text(const char *plaintext, unsigned long long int *ciphertext, int *cipher_len, uint32_t n, uint16_t e)
{
	int i;
	*cipher_len = 0;
	
	printf("\n--- Encryption Process ---\n");
	printf("Encrypting each character:\n");
	
	for (i = 0; plaintext[i] != '\0' && plaintext[i] != '\n'; i++)
	{
		unsigned char ch = plaintext[i];
		ciphertext[i] = modpow_encrypt(ch, e, n);
		printf("  '%c' (ASCII %d) -> c = %d^%d mod %d = %llu\n", 
		       ch, ch, ch, e, n, ciphertext[i]);
		(*cipher_len)++;
	}
}

// ============ Decryption Functions ============

unsigned long long int modpow_decrypt(unsigned long long int base, int power, int mod)
{
	int i;
	unsigned long long int result = 1;
	for (i = 0; i < power; i++)
	{
		result = (result * base) % mod;
	}
	return result;
}

int inverse(int a, int mod)
{
	int aprev, iprev, i = 1, atemp, itemp;
	
	aprev = mod, iprev = mod;
	while (a != 1)
	{
		atemp = a;
		itemp = i;
		a = aprev - aprev / atemp * a;
		i = iprev - aprev / atemp * i;
		aprev = atemp;
		iprev = itemp;
		while (i < 0)
			i += mod;
	}
	
	return i;
}

void decrypt_text(unsigned long long int *ciphertext, int cipher_len, char *plaintext, 
                  uint32_t n, uint32_t d, uint16_t p, uint16_t q)
{
	int i;
	unsigned long long int dP, dQ, m1, m2;
	int qInv, m1m2, h, m;
	
	printf("\n--- Decryption Process ---\n");
	printf("Using Chinese Remainder Theorem (CRT):\n");
	printf("  dP = d mod (p-1) = %"PRIu32" mod %d = %"PRIu32"\n", d, p-1, (uint32_t)(d % (p-1)));
	printf("  dQ = d mod (q-1) = %"PRIu32" mod %d = %"PRIu32"\n", d, q-1, (uint32_t)(d % (q-1)));
	
	dP = d % (p - 1);
	dQ = d % (q - 1);
	qInv = inverse(q, p);
	
	printf("  qInv = inverse(q, p) = inverse(%d, %d) = %d\n\n", q, p, qInv);
	printf("Decrypting each ciphertext value:\n");
	
	for (i = 0; i < cipher_len; i++)
	{
		unsigned long long int c = ciphertext[i];
		m1 = modpow_decrypt(c, dP, p);
		m2 = modpow_decrypt(c, dQ, q);
		m1m2 = m1 - m2;
		if (m1m2 < 0)
			m1m2 += p;
		h = (qInv * m1m2) % p;
		m = m2 + h * q;
		plaintext[i] = (char)m;
		printf("  c=%llu -> m1=%llu, m2=%llu, h=%d -> m=%d -> '%c'\n", 
		       c, m1, m2, h, m, (char)m);
	}
	plaintext[cipher_len] = '\0';
}

// ============ Main Interactive Program ============

int main()
{
	uint16_t e = E_VALUE, p, q;
	uint32_t n, phi, d;
	char plaintext[MAX_TEXT_LENGTH];
	unsigned long long int ciphertext[MAX_TEXT_LENGTH];
	char decrypted[MAX_TEXT_LENGTH];
	int cipher_len;
	
	srand(time(NULL));
	
	printf("========================================\n");
	printf("   Interactive RSA Encryption System\n");
	printf("========================================\n\n");
	
	// Generate RSA keys
	printf("Step 1: Generating RSA Keys...\n");
	printf("-------------------------------\n");
	printf("Using e = %"PRIu16"\n", e);
	
	setprimes(e, &p, &q, &n, &phi);
	
	printf("Generated prime numbers:\n");
	printf("  p = %"PRIu16"\n", p);
	printf("  q = %"PRIu16"\n", q);
	printf("  n = p * q = %"PRIu32"\n", n);
	printf("  phi(n) = (p-1)*(q-1) = %"PRIu32"\n", phi);
	
	d = findD(e, phi);
	printf("  d = %"PRIu32" (modular inverse of e mod phi)\n\n", d);
	
	printf("Public Key:  (n=%"PRIu32", e=%"PRIu16")\n", n, e);
	printf("Private Key: (n=%"PRIu32", d=%"PRIu32")\n\n", n, d);
	
	// Get user input
	printf("========================================\n");
	printf("Step 2: Enter Text to Encrypt\n");
	printf("-------------------------------\n");
	printf("Enter your message: ");
	
	if (fgets(plaintext, MAX_TEXT_LENGTH, stdin) == NULL)
	{
		printf("Error reading input\n");
		return 1;
	}
	
	// Remove newline if present
	size_t len = strlen(plaintext);
	if (len > 0 && plaintext[len-1] == '\n')
		plaintext[len-1] = '\0';
	
	printf("\nOriginal message: \"%s\"\n", plaintext);
	
	// Encrypt
	printf("\n========================================\n");
	printf("Step 3: Encryption\n");
	printf("========================================\n");
	encrypt_text(plaintext, ciphertext, &cipher_len, n, e);
	
	printf("\nCiphertext values: ");
	for (int i = 0; i < cipher_len; i++)
	{
		printf("%llu ", ciphertext[i]);
	}
	printf("\n");
	
	// Decrypt
	printf("\n========================================\n");
	printf("Step 4: Decryption\n");
	printf("========================================\n");
	decrypt_text(ciphertext, cipher_len, decrypted, n, d, p, q);
	
	printf("\n========================================\n");
	printf("Results\n");
	printf("========================================\n");
	printf("Original message:  \"%s\"\n", plaintext);
	printf("Decrypted message: \"%s\"\n", decrypted);
	
	if (strcmp(plaintext, decrypted) == 0)
	{
		printf("\n✓ SUCCESS: Decryption matches original!\n");
	}
	else
	{
		printf("\n✗ ERROR: Decryption does not match original!\n");
	}
	
	printf("========================================\n");
	
	return 0;
}
