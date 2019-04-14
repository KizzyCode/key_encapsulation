//
// Created by Keziah Biermann on 2019-04-04.
//

#ifndef KYNC_KYNC_H
#define KYNC_KYNC_H

#include <stddef.h>
#include <stdint.h>


/// A thread-local error
typedef struct {
	/// The error type as UTF-8 data; *MAY* be `NULL` if no error occurred
	uint8_t const* error_type;
	/// The length of `error_type` (without the trailing `\0` byte if any)
	size_t error_type_len;
	
	/// The error description or an empty string
	uint8_t const* description;
	/// The length of `description` (without the trailing `\0` byte if any)
	size_t description_len;
	
	/// Some error specific info
	uint64_t info;
} error_t;


/// Initializes the plugin
///
/// \param api_version A pointer to an integer to write the plugin's API version to
/// \param log_level The log level the plugin should use (only applies to stderr)
void init(uint8_t* api_version, uint8_t log_level);


/// Computes the buffer size necessary for a call to `fn_name` which will process `input_len` bytes
/// of input and writes the result to `buf_len`
///
/// \param buf_len A pointer to an integer to write the computed buffer length to
/// \param fn_name The function name
/// \param fn_name_len The length of `fn_name`
/// \param input_len The amount of input bytes the function will process
void buf_len(size_t* buf_len, uint8_t const* fn_name, size_t fn_name_len, size_t input_len);


/// Writes the plugin UID to `uid`
///
/// \param uid A pointer to a pointer to write format UID to
/// \param uid_written A pointer to an integer to reflect the amount of bytes written to `uid`
void capsule_format_uid(uint8_t* uid, size_t* uid_written);

/// Writes all crypto item IDs as `\0`-terminated, concatenated UTF-8 strings to `buf`
///
/// \param buf The buffer to write the concatenated crypto item UIDs to
/// \param buf_written A pointer to an integer to reflect the amount of bytes written to `buf`
/// \return Either `NULL` in case of success or a pointer to the thread-local error struct
error_t const* crypto_item_ids(uint8_t* buf, size_t* buf_written);


/// Seals `key` into `buf`
///
/// \param buf The buffer to write the sealed key to
/// \param buf_written A pointer to an integer to reflect the amount of bytes written to `buf`
/// \param key The key to seal
/// \param key_len The length of `key`
/// \param crypto_item_id The crypt item to use (may be `NULL`; see specification)
/// \param crypto_item_id_len The length of `crypto_item_uid`
/// \param user_secret The user secret to use (may be `NULL`; see specification)
/// \param user_secret_len The length of `user_secret`
/// \return Either `NULL` in case of success or a pointer to the thread-local error struct
error_t const* seal(
	uint8_t* buf, size_t* buf_written,
	uint8_t const* key, size_t key_len,
	uint8_t const* crypto_item_id, size_t crypto_item_id_len,
	uint8_t const* user_secret, size_t user_secret_len
);


/// Opens `capsule` into `buf`
///
/// \param buf The buffer to write the opened key to
/// \param buf_written A pointer to an integer to reflect the amount of bytes written to `buf`
/// \param capsule The capsule to open
/// \param capsule_len The length of `capsule`
/// \param user_secret The user secret to use (may be `NULL`; see specification)
/// \param user_secret_len The length of `user_secret`
/// \return Either `NULL` in case of success or a pointer to the thread-local error struct
error_t const* open(
	uint8_t* buf, size_t* buf_written,
	uint8_t const* capsule, size_t capsule_len,
	uint8_t const* user_secret, size_t user_secret_len
);


#endif //KYNC_KYNC_H
