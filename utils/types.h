#ifndef _TYPES_H
#define _TYPES_H

#include <stdlib.h>

#define PACKED_TYPE(type, def)	\
	typedef def __attribute__ ((__packed__)) type;


#define INIT_DATA_LEN (CTAP_MAX_REPORT_LEN - CTAP_INIT_HEADER_LEN)
#define CONT_DATA_LEN (CTAP_MAX_REPORT_LEN - CTAP_HEADER_HEADER_LEN)

#ifndef FIDO_MAXMSG_CRED
#define FIDO_MAXMSG_CRED	4096
#endif


/*
    BLOB TYPES
*/

typedef struct fido_blob {
	unsigned char	*ptr;
	size_t		 len;
} fido_blob_t;

typedef struct fido_blob_array {
	fido_blob_t	*ptr;
	size_t		 len;
} fido_blob_array_t;

/*
    END BLOB TYPES
*/


/*
    PUBLIC KEY TYPES
*/

typedef struct es256_pk {
	unsigned char	x[32];
	unsigned char	y[32];
} es256_pk_t;

/* COSE ES256 (ECDSA over P-256 with SHA-256) (secret) key */
typedef struct es256_sk {
	unsigned char	d[32];
} es256_sk_t;

/* COSE RS256 (2048-bit RSA with PKCS1 padding and SHA-256) public key */
typedef struct rs256_pk {
	unsigned char n[256];
	unsigned char e[3];
} rs256_pk_t;

/* COSE EDDSA (ED25519) */
typedef struct eddsa_pk {
	unsigned char x[32];
} eddsa_pk_t;


typedef struct fido_attcred {
	unsigned char aaguid[16]; /* credential's aaguid */
	fido_blob_t   id;         /* credential id */
	int           type;       /* credential's cose algorithm */
	union {                   /* credential's public key */
		es256_pk_t es256;
		rs256_pk_t rs256;
		eddsa_pk_t eddsa;
	} pubkey;
} fido_attcred_t;

typedef struct fido_attstmt {
	fido_blob_t certinfo; /* tpm attestation TPMS_ATTEST structure */
	fido_blob_t pubarea;  /* tpm attestation TPMT_PUBLIC structure */
	fido_blob_t cbor;     /* cbor-encoded attestation statement */
	fido_blob_t x5c;      /* attestation certificate */
	fido_blob_t sig;      /* attestation signature */
	int         alg;      /* attestation algorithm (cose) */
} fido_attstmt_t;

typedef struct fido_rp {
	char *id;   /* relying party id */
	char *name; /* relying party name */
} fido_rp_t;

typedef struct fido_user {
	fido_blob_t  id;           /* required */
	char        *icon;         /* optional */
	char        *name;         /* optional */
	char        *display_name; /* required */
} fido_user_t;

typedef struct fido_cred_ext {
	int    mask;      /* enabled extensions */
	int    prot;      /* protection policy */
	size_t minpinlen; /* minimum pin length */
} fido_cred_ext_t;

PACKED_TYPE(fido_authdata_t,
struct fido_authdata {
	unsigned char rp_id_hash[32]; /* sha256 of fido_rp.id */
	uint8_t       flags;          /* user present/verified */
	uint32_t      sigcount;       /* signature counter */
	/* actually longer */
})

typedef struct fido_cred {
	fido_blob_t       cd;            /* client data */
	fido_blob_t       cdh;           /* client data hash */
	fido_rp_t         rp;            /* relying party */
	fido_user_t       user;          /* user entity */
	fido_blob_array_t excl;          /* list of credential ids to exclude */
	fido_opt_t        rk;            /* resident key */
	fido_opt_t        uv;            /* user verification */
	fido_cred_ext_t   ext;           /* extensions */
	int               type;          /* cose algorithm */
	char             *fmt;           /* credential format */
	fido_cred_ext_t   authdata_ext;  /* decoded extensions */
	fido_blob_t       authdata_cbor; /* cbor-encoded payload */
	fido_blob_t       authdata_raw;  /* cbor-decoded payload */
	fido_authdata_t   authdata;      /* decoded authdata payload */
	fido_attcred_t    attcred;       /* returned credential (key + id) */
	fido_attstmt_t    attstmt;       /* attestation statement (x509 + sig) */
	fido_blob_t       largeblob_key; /* decoded large blob key */
	fido_blob_t       blob;          /* CTAP 2.1 credBlob */
	fido_blob_t       attObject_cbor;/* cbor-encoded attestation object (with ftm + attstmt + authdata) */
} fido_cred_t;

typedef struct fido_assert_extattr {
	int         mask;            /* decoded extensions */
	fido_blob_t hmac_secret_enc; /* hmac secret, encrypted */
	fido_blob_t blob;            /* decoded CTAP 2.1 credBlob */
} fido_assert_extattr_t;

typedef struct _fido_assert_stmt {
	fido_blob_t           id;            /* credential id */
	fido_user_t           user;          /* user attributes */
	fido_blob_t           hmac_secret;   /* hmac secret */
	fido_assert_extattr_t authdata_ext;  /* decoded extensions */
	fido_blob_t           authdata_cbor; /* raw cbor payload */
	fido_authdata_t       authdata;      /* decoded authdata payload */
	fido_blob_t           sig;           /* signature of cdh + authdata */
	fido_blob_t           largeblob_key; /* decoded large blob key */
} fido_assert_stmt;

typedef struct fido_assert_ext {
	int         mask;                /* enabled extensions */
	fido_blob_t hmac_salt;           /* optional hmac-secret salt */
} fido_assert_ext_t;

typedef struct fido_assert {
	char              *rp_id;        /* relying party id */
	fido_blob_t        cd;           /* client data */
	fido_blob_t        cdh;          /* client data hash */
	fido_blob_array_t  allow_list;   /* list of allowed credentials */
	fido_opt_t         up;           /* user presence */
	fido_opt_t         uv;           /* user verification */
	fido_assert_ext_t  ext;          /* enabled extensions */
	fido_assert_stmt  *stmt;         /* array of expected assertions */
	size_t             stmt_cnt;     /* number of allocated assertions */
	size_t             stmt_len;     /* number of received assertions */
} fido_assert_t;

typedef struct frame {
	uint32_t cid; /* channel id */
	union {
		uint8_t type;
		struct {
			uint8_t cmd;
			uint8_t bcnth;
			uint8_t bcntl;
			uint8_t data[CTAP_MAX_REPORT_LEN - CTAP_INIT_HEADER_LEN];
		} init;
		struct {
			uint8_t seq;
			uint8_t data[CTAP_MAX_REPORT_LEN - CTAP_CONT_HEADER_LEN];
		} cont;
	} body;
} frame_t;

typedef struct fido_dev_info {
	char                 *path;         /* device path */
	int16_t               vendor_id;    /* 2-byte vendor id */
	int16_t               product_id;   /* 2-byte product id */
	char                 *manufacturer; /* manufacturer string */
	char                 *product;      /* product string */
	fido_dev_io_t         io;           /* i/o functions */
	fido_dev_transport_t  transport;    /* transport functions */
} fido_dev_info_t;

PACKED_TYPE(fido_ctap_info_t,
/* defined in section 8.1.9.1.3 (CTAPHID_INIT) of the fido2 ctap spec */
struct fido_ctap_info {
	uint64_t nonce;    /* echoed nonce */
	uint32_t cid;      /* channel id */
	uint8_t  protocol; /* ctaphid protocol id */
	uint8_t  major;    /* major version number */
	uint8_t  minor;    /* minor version number */
	uint8_t  build;    /* build version number */
	uint8_t  flags;    /* capabilities flags; see FIDO_CAP_* */
});

typedef struct fido_dev {
	uint64_t              nonce;      /* issued nonce */
	fido_ctap_info_t      attr;       /* device attributes */
	uint32_t              cid;        /* assigned channel id */
	char                 *path;       /* device path */
	void                 *io_handle;  /* abstract i/o handle */
	fido_dev_io_t         io;         /* i/o functions */
	bool                  io_own;     /* device has own io/transport */
	size_t                rx_len;     /* length of HID input reports */
	size_t                tx_len;     /* length of HID output reports */
	int                   flags;      /* internal flags; see FIDO_DEV_* */
	fido_dev_transport_t  transport;  /* transport functions */
	uint64_t	      maxmsgsize; /* max message size */
	int		      timeout_ms; /* read timeout in ms */
} fido_dev_t;

typedef struct write_parameters {
	int fd;
	const void *buf;
	size_t count; 
} write_parameters_t;

typedef struct read_parameters {
	int fd;
	void *buf;
	size_t count; 
} read_parameters_t;

typedef struct attack_flags {
	uint8_t mitm_attack;
	uint8_t swap_attack;
} attack_flags_t;

typedef struct state_helper {
    int fd;
	int bad_token_fd;
    uint32_t cid;
    uint8_t command;
    uint8_t ctap_command;
    uint8_t ctap_sub_command;
    uint8_t packets_read; // how many packets were read by the client (how many packets we actually let the client have so far)
    uint8_t is_last_packet;
    size_t writen_so_far;   
    size_t client_read_so_far;
    unsigned char cbor_payload[2048];
	int cbor_payload_index;
	size_t payload_len;
	unsigned char original_cbor_payload[2048];
	int original_cbor_payload_index;
	size_t original_payload_len;
	fido_blob_t *hooked_token_public_key;
	int hooked_token_public_key_index;
    frame_t frames[128];
    uint8_t frame_count; // how many frames were read/written from/to the token
	uint8_t expected_frames;
    uint8_t modify_cbor;
    uint8_t swap_token;
	// If set to 1, the next write operation will delete the file and avoid the attack completely
	uint8_t delete_on_next_write;
    fido_blob_t *token_shared_secret;
    fido_blob_t *client_shared_secret;
	fido_dev_t* bad_token_dev;
	char bad_token_pin[64];
	fido_blob_t* bad_token_ecdh_secret;
	fido_blob_t* bad_token_pin_token;
	write_parameters_t *write_parameters;
	read_parameters_t *read_parameters;
	attack_flags_t *attack_flags;
	uint8_t deactivate_attack;
	uint8_t protocol;
} state_helper_t;

struct cose_key {
	int kty;
	int alg;
	int crv;
};


#endif