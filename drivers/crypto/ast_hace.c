#include <common.h>

#ifdef CONFIG_SHA_HW_ACCEL
#include <u-boot/sha256.h>
#include <u-boot/sha1.h>
#include <asm/errno.h>
#include <asm/io.h>

#define AST_HACE_HASH_ALGO_SHA1		2
#define AST_HACE_HASH_ALGO_SHA256	5

#define AST_HACE_REGISTER_BASE						0x1e6e3000
#define AST_HACE_REGISTER_STATUS					AST_HACE_REGISTER_BASE + 0x1C
#define AST_HACE_REGISTER_HASH_DATA_SOURCE_ADDRESS	AST_HACE_REGISTER_BASE + 0x20
#define AST_HACE_REGISTER_HASH_DIGEST_WRITE_ADDRESS	AST_HACE_REGISTER_BASE + 0x24
#define AST_HACE_REGISTER_HASH_DATA_LENGTH			AST_HACE_REGISTER_BASE + 0x2C
#define AST_HACE_REGISTER_HASH_CONTROL				AST_HACE_REGISTER_BASE + 0x30

#define AST_HACE_STATUS_HASH_BUSY	(1U << 0)


int aspeed_hace_hash_digest(const unsigned char *pbuf, unsigned int buf_len,
            unsigned char *pout, unsigned int hash_type) {
	if ((readl(AST_HACE_REGISTER_STATUS) & AST_HACE_STATUS_HASH_BUSY) != 0) {
		return -EBUSY;
	}

	writel((unsigned int)pbuf, AST_HACE_REGISTER_HASH_DATA_SOURCE_ADDRESS);
	writel(buf_len, AST_HACE_REGISTER_HASH_DATA_LENGTH);
	writel((unsigned int)pout, AST_HACE_REGISTER_HASH_DIGEST_WRITE_ADDRESS);

	switch (hash_type) {
		case AST_HACE_HASH_ALGO_SHA1:
			writel(0x28, AST_HACE_REGISTER_HASH_CONTROL);
			break;
		case AST_HACE_HASH_ALGO_SHA256:
			writel(0x58, AST_HACE_REGISTER_HASH_CONTROL);
			break;
		default:
			return -ENOSYS;
	}

	while ((readl(AST_HACE_REGISTER_STATUS) & AST_HACE_STATUS_HASH_BUSY) != 0);

    return 0;
}

void hw_sha256(const unsigned char *pbuf, unsigned int buf_len,
			unsigned char *pout, unsigned int chunk_size)
{
	if (aspeed_hace_hash_digest(pbuf, buf_len, pout, AST_HACE_HASH_ALGO_SHA256))
		debug("HACE was not setup properly or it is faulty\n");
}

void hw_sha1(const unsigned char *pbuf, unsigned int buf_len,
			unsigned char *pout, unsigned int chunk_size)
{
	if (aspeed_hace_hash_digest(pbuf, buf_len, pout, AST_HACE_HASH_ALGO_SHA1))
		debug("HACE was not setup properly or it is faulty\n");
}

#endif /* CONFIG_SHA_HW_ACCEL */
