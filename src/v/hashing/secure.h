/*
 * Copyright 2020 Vectorized, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */
#pragma once
#include "bytes/bytes.h"

#ifdef TP_BUILD
#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/mem.h>
#else
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#endif

class hmac_exception final : public std::exception {
public:
    explicit hmac_exception(const char* msg)
      : _msg(msg) {}

    const char* what() const noexcept final { return _msg; }

private:
    const char* _msg;
};

class hash_exception final : public std::exception {
public:
    explicit hash_exception(const char* msg)
      : _msg(msg) {}

    const char* what() const noexcept final { return _msg; }

private:
    const char* _msg;
};

namespace internal {

#ifdef TP_BUILD
template<size_t DigestSize>
#else
template<gnutls_mac_algorithm_t Algo, size_t DigestSize>
#endif
class hmac {
    static_assert(DigestSize > 0, "digest cannot be zero length");

public:
    // silence clang-tidy about _handle being uninitialized
    // NOLINTNEXTLINE(hicpp-member-init, cppcoreguidelines-pro-type-member-init)
    explicit hmac(std::string_view key)
      : hmac(key.data(), key.size()) {}

    // silence clang-tidy about _handle being uninitialized
    // NOLINTNEXTLINE(hicpp-member-init, cppcoreguidelines-pro-type-member-init)
    explicit hmac(bytes_view key)
      : hmac(key.data(), key.size()) {}

    hmac(const hmac&) = delete;
    hmac& operator=(const hmac&) = delete;
    hmac(hmac&&) = delete;
    hmac& operator=(hmac&&) = delete;

    ~hmac() noexcept {
#ifdef TP_BUILD
	HMAC_CTX_cleanup(&_ctx);
#else
        gnutls_hmac_deinit(_handle, nullptr);
#endif
    }

    void update(std::string_view data) { update(data.data(), data.size()); }
    void update(bytes_view data) { update(data.data(), data.size()); }

    template<std::size_t Size>
    void update(const std::array<char, Size>& data) {
        update(data.data(), Size);
    }

    /**
     * Return the current output and reset.
     */
    std::array<char, DigestSize> reset() {
        std::array<char, DigestSize> digest;
#ifdef TP_BUILD
	uint32_t size = 0;
        if (unlikely(!HMAC_Final(&_ctx, reinterpret_cast<uint8_t*>(digest.data()), &size))) {
            throw hmac_exception("failed to calculate final digest");
        }
#else
        gnutls_hmac_output(_handle, digest.data());
#endif
        return digest;
    }

private:
    // silence clang-tidy about _handle being uninitialized
    // NOLINTNEXTLINE(hicpp-member-init, cppcoreguidelines-pro-type-member-init)
    hmac(const void* key, size_t size) {
#ifdef TP_BUILD
        const EVP_MD * evp_md = nullptr;
	if constexpr (DigestSize == 32) {
            evp_md = EVP_sha256();
	} else if constexpr (DigestSize == 64) {
            evp_md = EVP_sha512();
	} else {
            throw hmac_exception("unsupported digest size");
	}

        HMAC_CTX_init(&_ctx);
	if (unlikely(!HMAC_Init_ex(&_ctx, key, size, evp_md, nullptr))) {
            throw hmac_exception("failed to init hmac ex");
	}

	if (HMAC_size(&_ctx) != DigestSize) {
            throw hmac_exception("invalid digest length");
	}
#else
        int ret = gnutls_hmac_init(&_handle, Algo, key, size);
        if (unlikely(ret)) {
            throw hmac_exception(gnutls_strerror(ret));
        }

        ret = gnutls_hmac_get_len(Algo);
        if (unlikely(ret != DigestSize)) {
            throw hmac_exception("invalid digest length");
        }
#endif
    }

    void update(const void* data, size_t size) {
#ifdef TP_BUILD
	if (unlikely(!HMAC_Update(&_ctx, reinterpret_cast<const uint8_t*>(data), size))) {
            throw hmac_exception("failed to update hmac");
        }
#else
        int ret = gnutls_hmac(_handle, data, size);
        if (unlikely(ret)) {
            throw hmac_exception(gnutls_strerror(ret));
        }
#endif
    }

#ifdef TP_BUILD
    HMAC_CTX _ctx;
#else
    gnutls_hmac_hd_t _handle;
#endif
};

#ifdef TP_BUILD
class hash256 {
public:
    hash256() {
        if (unlikely(SHA256_Init(&_ctx) != 1)) {
            throw hash_exception("failed to init sha256 context");
        }
    }

    ~hash256() noexcept {
        OPENSSL_cleanse(&_ctx, sizeof(_ctx));
    }

    hash256(const hash256&) = delete;
    hash256& operator=(const hash256&) = delete;
    hash256(hash256&&) = delete;
    hash256& operator=(hash256&&) = delete;

    void update(std::string_view data) { update(data.data(), data.size()); }
    void update(bytes_view data) { update(data.data(), data.size()); }

    /**
     * Return the current output and reset.
     */
    std::array<char, 32> reset() {
        std::array<char, 32> digest;
        SHA256_Final(reinterpret_cast<uint8_t*>(digest.data()), &_ctx);
        return digest;
    }

private:
    void update(const void* data, size_t size) {
        if (unlikely(SHA256_Update(&_ctx, reinterpret_cast<const uint8_t*>(data), size) != 1)) {
            throw hash_exception("failed to update sha256");
	}
    }

private:
    SHA256_CTX _ctx;
};

class hash512 {
public:
    hash512() {
        if (unlikely(SHA512_Init(&_ctx) != 1)) {
            throw hash_exception("failed to init sha256 context");
        }
    }

    ~hash512() noexcept {
        OPENSSL_cleanse(&_ctx, sizeof(_ctx));
    }

    hash512(const hash512&) = delete;
    hash512& operator=(const hash512&) = delete;
    hash512(hash512&&) = delete;
    hash512& operator=(hash512&&) = delete;

    void update(std::string_view data) { update(data.data(), data.size()); }
    void update(bytes_view data) { update(data.data(), data.size()); }

    /**
     * Return the current output and reset.
     */
    std::array<char, 32> reset() {
        std::array<char, 32> digest;
        SHA512_Final(reinterpret_cast<uint8_t*>(digest.data()), &_ctx);
        return digest;
    }

private:
    void update(const void* data, size_t size) {
        if (unlikely(SHA512_Update(&_ctx, static_cast<const uint8_t*>(data), size) != 1)) {
            throw hash_exception("failed to update sha512");
	}
    }

private:
    SHA512_CTX _ctx;
};

#else
template<gnutls_digest_algorithm_t Algo, size_t DigestSize>
class hash {
    static_assert(DigestSize > 0, "digest cannot be zero length");

public:
    // silence clang-tidy about _handle being uninitialized
    // NOLINTNEXTLINE(hicpp-member-init, cppcoreguidelines-pro-type-member-init)
    hash() {
        int ret = gnutls_hash_init(&_handle, Algo);
        if (unlikely(ret)) {
            throw hash_exception(gnutls_strerror(ret));
        }

        ret = gnutls_hash_get_len(Algo);
        if (unlikely(ret != DigestSize)) {
            throw hash_exception("invalid digest length");
        }
    }

    hash(const hash&) = delete;
    hash& operator=(const hash&) = delete;
    hash(hash&&) = delete;
    hash& operator=(hash&&) = delete;

    ~hash() noexcept { gnutls_hash_deinit(_handle, nullptr); }

    void update(std::string_view data) { update(data.data(), data.size()); }
    void update(bytes_view data) { update(data.data(), data.size()); }

    /**
     * Return the current output and reset.
     */
    std::array<char, DigestSize> reset() {
        std::array<char, DigestSize> digest;
        gnutls_hash_output(_handle, digest.data());
        return digest;
    }

private:
    void update(const void* data, size_t size) {
        int ret = gnutls_hash(_handle, data, size);
        if (unlikely(ret)) {
            throw hash_exception(gnutls_strerror(ret));
        }
    }

    gnutls_hash_hd_t _handle;
};
#endif

} // namespace internal

#ifdef TP_BUILD
using hmac_sha256 = internal::hmac<32>; // NOLINT
using hmac_sha512 = internal::hmac<64>; // NOLINT
#else
using hmac_sha256 = internal::hmac<GNUTLS_MAC_SHA256, 32>; // NOLINT
using hmac_sha512 = internal::hmac<GNUTLS_MAC_SHA512, 64>; // NOLINT
#endif

#ifdef TP_BUILD
using hash_sha256 = internal::hash256; // NOLINT
using hash_sha512 = internal::hash512; // NOLINT
#else
using hash_sha256 = internal::hash<GNUTLS_DIG_SHA256, 32>; // NOLINT
using hash_sha512 = internal::hash<GNUTLS_DIG_SHA512, 64>; // NOLINT
#endif
