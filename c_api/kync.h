#ifndef KYNC_H
#define KYNC_H

#include <stddef.h>
#include <stdint.h>


typedef struct slice_t slice_t;
/// A slice over some data
struct slice_t {
	/// The data
	const uint8_t* ptr;
	/// The data length
	const size_t len;
};


typedef struct write_t write_t;
/// A write callback
struct write_t {
	/// An opaque handle to the data sink
	void* handle;
	/// Pushes a segment to `handle` and returns `NULL` on success or a pointer to a static error
	/// description
	const char* (*write)(void* handle, const slice_t* data);
};


/// Initializes the library with a specific API version and a logging level
///
/// \param api The required API version
/// \param log_level The stderr logging level to use
/// \return `NULL` on success or a pointer to a static error description
typedef const char* (*init)(uint16_t api, uint8_t log_level);


/// Queries the plugin/format ID
///
/// \param sink The sink to write the ID to
/// \return `NULL` on success or a pointer to a static error description
typedef const char* (*id)(write_t* sink);


/// Queries all possible configs and writes them as separate segments
///
/// \param sink The sink to write the configs to (each config is a separate call to `write`)
/// \return `NULL` on success or a pointer to a static error description
typedef const char* (*configs)(write_t* sink);


/// Sets an optional application specific context if supported (useful to assign better names etc.)
///
/// \param context The context to set
/// \return `NULL` on success/if unsupported or a pointer to a static error description if a context
///         is supported by the plugin but could not be set
typedef const char* (*set_context)(const slice_t* context);


/// Queries the authentication requirements to protect a secret for a specific config
///
/// \param is_required Is set to `1` if an authentication is required, `0` otherwise
/// \param retries Is set to the amount of retries left or `UINT64_MAX` if there is no limit
/// \param config The configuration to get the requirements for
/// \return `NULL` on success or a pointer to a static error description
typedef const char* (*auth_info_protect)(uint8_t* is_required, uint64_t* retries, const slice_t* config);


/// Queries the authentication requirements to recover a secret for a specific config
///
/// \param is_required Is set to `1` if an authentication is required, `0` otherwise
/// \param retries Is set to the amount of retries left or `UINT64_MAX` if there is no limit
/// \param config The configuration to get the requirements for
/// \return `NULL` on success or a pointer to a static error description
typedef const char* (*auth_info_recover)(uint8_t* is_required, uint64_t* retries, const slice_t* config);


/// Protects some data
///
/// \param sink The sink to write the recovery information to
/// \param data The data to seal
/// \param auth The authentication data (may be `NULL` if no authentication should be performed)
/// \param config The config to use
/// \return `NULL` on success or a pointer to a static error description
typedef const char* (*protect)(write_t* sink, const slice_t* data, const slice_t* config, const slice_t* auth);


/// Opens `data` to `sink` using `auth` and `config`
///
/// \param sink The sink to write the recovered data to
/// \param data The recovery information
/// \param auth The authentication data (may be `NULL` if no authentication should be performed)
/// \return `NULL` on success or a pointer to a static error description
typedef const char* (*recover)(write_t* sink, const slice_t* data, const slice_t* auth);


#endif //KYNC_H
