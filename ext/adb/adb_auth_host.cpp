/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG AUTH

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <sys/inotify.h>
#endif

#include <map>
#include <mutex>
#include <set>
#include <string>

#include <android-base/errors.h>
#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
//#include <openssl/base64.h>
//#include <openssl/evp.h>
//#include <openssl/objects.h>
//#include <openssl/pem.h>
//#include <openssl/rsa.h>
//#include <openssl/sha.h>

#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include <openssl/applink.c>

#include "adb.h"
#include "adb_auth.h"
#include "adb_utils.h"
#include "sysdeps.h"
#include "transport.h"

#define RSANUMBYTES 256           /* 2048 bit key length */
#define RSANUMWORDS (RSANUMBYTES / sizeof(unsigned int))

typedef struct RSAPublicKey {
	int len;                  /* Length of n[] in number of uint32_t */
	unsigned int n0inv;           /* -1 / n[0] mod 2^32 */
	unsigned int n[RSANUMWORDS];  /* modulus as little endian array */
	unsigned int rr[RSANUMWORDS]; /* R^2 as little endian array */
	int exponent;             /* 3 or 65537 */
} RSAPublicKey;

#ifndef S_ISDIR
#define S_ISDIR(x) ((x) & _S_IFDIR)
#endif

static std::mutex& g_keys_mutex = *new std::mutex;
static std::map<std::string, std::shared_ptr<RSA>>& g_keys =
    *new std::map<std::string, std::shared_ptr<RSA>>;
static std::map<int, std::string>& g_monitored_paths = *new std::map<int, std::string>;

static std::string get_user_info() {
    //LOG(INFO) << "get_user_info...";

    std::string hostname;
    if (getenv("HOSTNAME")) hostname = getenv("HOSTNAME");
#if !defined(_WIN32)
    char buf[64];
    if (hostname.empty() && gethostname(buf, sizeof(buf)) != -1) hostname = buf;
#endif
    if (hostname.empty()) hostname = "unknown";

    std::string username;
    if (getenv("LOGNAME")) username = getenv("LOGNAME");
#if !defined _WIN32 && !defined ADB_HOST_ON_TARGET
    if (username.empty() && getlogin()) username = getlogin();
#endif
    if (username.empty()) hostname = "unknown";

    return " " + username + "@" + hostname;
}

/* Convert OpenSSL RSA private key to android pre-computed RSAPublicKey format */
//joexie
static int RSA_to_RSAPublicKey(RSA *rsa, RSAPublicKey *pkey)
{
	int ret = 1;
	unsigned int i;

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* r32 = BN_new();
	BIGNUM* rr = BN_new();
	BIGNUM* r = BN_new();
	BIGNUM* rem = BN_new();
	BIGNUM* n = BN_new();
	BIGNUM* n0inv = BN_new();

	if (RSA_size(rsa) != RSANUMBYTES) {
		ret = 0;
		goto out;
	}

	BN_set_bit(r32, 32);
	BN_copy(n, rsa->n);
	BN_set_bit(r, RSANUMWORDS * 32);
	BN_mod_sqr(rr, r, n, ctx);
	BN_div(NULL, rem, n, r32, ctx);
	BN_mod_inverse(n0inv, rem, r32, ctx);

	pkey->len = RSANUMWORDS;
	pkey->n0inv = 0 - BN_get_word(n0inv);
	for (i = 0; i < RSANUMWORDS; i++) {
		BN_div(rr, rem, rr, r32, ctx);
		pkey->rr[i] = BN_get_word(rem);
		BN_div(n, rem, n, r32, ctx);
		pkey->n[i] = BN_get_word(rem);
	}
	pkey->exponent = BN_get_word(rsa->e);

out:
	BN_free(n0inv);
	BN_free(n);
	BN_free(rem);
	BN_free(r);
	BN_free(rr);
	BN_free(r32);
	BN_CTX_free(ctx);

	return ret;
}

static void get_user_info(char *buf, size_t len)
{
	char hostname[1024], username[1024];
	int ret;

#ifndef _WIN32
	ret = gethostname(hostname, sizeof(hostname));
	if (ret < 0)
#endif
		strcpy(hostname, "unknown");

#if !defined _WIN32 && !defined ADB_HOST_ON_TARGET
	ret = getlogin_r(username, sizeof(username));
	if (ret < 0)
#endif
		strcpy(username, "unknown");

	ret = _snprintf(buf, len, " %s@%s", username, hostname);
	if (ret >= (signed)len)
		buf[len - 1] = '\0';
}

static bool write_public_keyfile(RSA* private_key, const std::string& private_key_path) {
    //LOG(INFO) << "write_public_keyfile...";

    //uint8_t binary_key_data[ANDROID_PUBKEY_ENCODED_SIZE];
    //if (!android_pubkey_encode(private_key, binary_key_data, sizeof(binary_key_data))) {
    //    //LOG(ERROR) << "Failed to convert to public key";
    //    return false;
    //}

    //size_t base64_key_length;
    //if (!EVP_EncodedLength(&base64_key_length, sizeof(binary_key_data))) {
    //    //LOG(ERROR) << "Public key too large to base64 encode";
    //    return false;
    //}

    //std::string content;
    //content.resize(base64_key_length);
    //base64_key_length = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(&content[0]), binary_key_data,
    //                                    sizeof(binary_key_data));

    //content += get_user_info();

    //std::string path(private_key_path + ".pub");
    //if (!android::base::WriteStringToFile(content, path)) {
    //    //PLOG(ERROR) << "Failed to write public key to '" << path << "'";
    //    return false;
    //}

    //return true;
	RSAPublicKey pkey;
	BIO *bio, *b64, *bfile;
	char path[MAX_PATH], info[MAX_PAYLOAD];
	int ret;

	ret = _snprintf(path, sizeof(path), "%s.pub", private_key_path.c_str());
	if (ret >= (signed)sizeof(path))
		return 0;

	ret = RSA_to_RSAPublicKey(private_key, &pkey);
	if (!ret) {
		D("Failed to convert to publickey\n");
		return 0;
	}

	bfile = BIO_new_file(path, "w");
	if (!bfile) {
		D("Failed to open '%s'\n", path);
		return 0;
	}

	D("Writing public key to '%s'\n", path);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_push(b64, bfile);
	BIO_write(bio, &pkey, sizeof(pkey));
	BIO_flush(bio);
	BIO_pop(b64);
	BIO_free(b64);

	get_user_info(info, sizeof(info));
	BIO_write(bfile, info, strlen(info));
	BIO_flush(bfile);
	BIO_free_all(bfile);

	return 1;
}

static int generate_key(const std::string& file) {
   // LOG(INFO) << "generate_key(" << file << ")...";

    int old_mask;
    FILE *f = NULL;
    int ret = 0;

    EVP_PKEY* pkey = EVP_PKEY_new();
    BIGNUM* exponent = BN_new();
    RSA* rsa = RSA_new();
    if (!pkey || !exponent || !rsa) {
        //LOG(ERROR) << "Failed to allocate key";
        goto out;
    }

    BN_set_word(exponent, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, exponent, NULL);
    EVP_PKEY_set1_RSA(pkey, rsa);

    old_mask = umask(077);

    f = fopen(file.c_str(), "w");
    if (!f) {
        //PLOG(ERROR) << "Failed to open " << file;
        umask(old_mask);
        goto out;
    }

    umask(old_mask);

    if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
        D("Failed to write key");
        goto out;
    }

    if (!write_public_keyfile(rsa, file)) {
        D("Failed to write public key");
        goto out;
    }

    ret = 1;

out:
    if (f) fclose(f);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BN_free(exponent);
    return ret;
}

static std::string hash_key(RSA* key) {
    unsigned char* pubkey = nullptr;
    int len = i2d_RSA_PUBKEY(key, &pubkey);
    if (len < 0) {
        //LOG(ERROR) << "failed to encode RSA public key";
        return std::string();
    }

    std::string result;
    result.resize(SHA256_DIGEST_LENGTH);
    SHA256(pubkey, len, reinterpret_cast<unsigned char*>(&result[0]));
    OPENSSL_free(pubkey);
    return result;
}

static bool read_key_file(const std::string& file) {
    //LOG(INFO) << "read_key_file '" << file << "'...";

    std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(file.c_str(), "r"), fclose);
    if (!fp) {
        //PLOG(ERROR) << "Failed to open '" << file << "'";
        return false;
    }

    RSA* key = RSA_new();
    if (!PEM_read_RSAPrivateKey(fp.get(), &key, nullptr, nullptr)) {
        //LOG(ERROR) << "Failed to read key";
        RSA_free(key);
        return false;
    }

    std::lock_guard<std::mutex> lock(g_keys_mutex);
    std::string fingerprint = hash_key(key);
    if (g_keys.find(fingerprint) != g_keys.end()) {
        //LOG(INFO) << "ignoring already-loaded key: " << file;
        RSA_free(key);
    } else {
        g_keys[fingerprint] = std::shared_ptr<RSA>(key, RSA_free);
    }

    return true;
}

static bool read_keys(const std::string& path, bool allow_dir = true) {
    //LOG(INFO) << "read_keys '" << path << "'...";

    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
       // PLOG(ERROR) << "failed to stat '" << path << "'";
        return false;
    }

    if (S_ISREG(st.st_mode)) {
        if (!android::base::EndsWith(path, ".adb_key")) {
            //LOG(INFO) << "skipping non-adb_key '" << path << "'";
            return false;
        }

        return read_key_file(path);
    } else if (S_ISDIR(st.st_mode)) {
        if (!allow_dir) {
            // inotify isn't recursive. It would break expectations to load keys in nested
            // directories but not monitor them for new keys.
            //LOG(WARNING) << "refusing to recurse into directory '" << path << "'";
            return false;
        }

        std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
        if (!dir) {
            //PLOG(ERROR) << "failed to open directory '" << path << "'";
            return false;
        }

        bool result = false;
        while (struct dirent* dent = readdir(dir.get())) {
            std::string name = dent->d_name;

            // We can't use dent->d_type here because it's not available on Windows.
            if (name == "." || name == "..") {
                continue;
            }

            result |= read_keys((path + OS_PATH_SEPARATOR + name).c_str(), false);
        }
        return result;
    }

    //LOG(ERROR) << "unexpected type for '" << path << "': 0x" << std::hex << st.st_mode;
    return false;
}

static std::string get_user_key_path() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + "adbkey";
}

static bool get_user_key() {
    std::string path = get_user_key_path();
    if (path.empty()) {
        //PLOG(ERROR) << "Error getting user key filename";
        return false;
    }

    struct stat buf;
    if (stat(path.c_str(), &buf) == -1) {
        //LOG(INFO) << "User key '" << path << "' does not exist...";
        if (!generate_key(path)) {
            //LOG(ERROR) << "Failed to generate new key";
            return false;
        }
    }

    return read_key_file(path);
}

static std::set<std::string> get_vendor_keys() {
    const char* adb_keys_path = getenv("ADB_VENDOR_KEYS");
    if (adb_keys_path == nullptr) {
        return std::set<std::string>();
    }

    std::set<std::string> result;
    for (const auto& path : android::base::Split(adb_keys_path, ENV_PATH_SEPARATOR_STR)) {
        result.emplace(path);
    }
    return result;
}

std::deque<std::shared_ptr<RSA>> adb_auth_get_private_keys() {
    std::deque<std::shared_ptr<RSA>> result;

    // Copy all the currently known keys.
    std::lock_guard<std::mutex> lock(g_keys_mutex);
    for (const auto& it : g_keys) {
        result.push_back(it.second);
    }

    // Add a sentinel to the list. Our caller uses this to mean "out of private keys,
    // but try using the public key" (the empty deque could otherwise mean this _or_
    // that this function hasn't been called yet to request the keys).
    result.push_back(nullptr);

    return result;
}

static int adb_auth_sign(RSA* key, const char* token, size_t token_size, char* sig) {
    if (token_size != TOKEN_SIZE) {
        D("Unexpected token size %zd", token_size);
        return 0;
    }

    unsigned int len;
    if (!RSA_sign(NID_sha1, reinterpret_cast<const uint8_t*>(token), token_size,
                  reinterpret_cast<uint8_t*>(sig), &len, key)) {
        return 0;
    }

    D("adb_auth_sign len=%d", len);
    return (int)len;
}

std::string adb_auth_get_userkey() {
    std::string path = get_user_key_path();
    if (path.empty()) {
        //PLOG(ERROR) << "Error getting user key filename";
        return "";
    }
    path += ".pub";

    std::string content;
    if (!android::base::ReadFileToString(path, &content)) {
        //PLOG(ERROR) << "Can't load '" << path << "'";
        return "";
    }
    return content;
}

int adb_auth_keygen(const char* filename) {
    return (generate_key(filename) == 0);
}

#if defined(__linux__)
static void adb_auth_inotify_update(int fd, unsigned fd_event, void*) {
    LOG(INFO) << "adb_auth_inotify_update called";
    if (!(fd_event & FDE_READ)) {
        return;
    }

    char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
    while (true) {
        ssize_t rc = TEMP_FAILURE_RETRY(unix_read(fd, buf, sizeof(buf)));
        if (rc == -1) {
            if (errno == EAGAIN) {
                LOG(INFO) << "done reading inotify fd";
                break;
            }
            PLOG(FATAL) << "read of inotify event failed";
        }

        // The read potentially returned multiple events.
        char* start = buf;
        char* end = buf + rc;

        while (start < end) {
            inotify_event* event = reinterpret_cast<inotify_event*>(start);
            auto root_it = g_monitored_paths.find(event->wd);
            if (root_it == g_monitored_paths.end()) {
                LOG(FATAL) << "observed inotify event for unmonitored path, wd = " << event->wd;
            }

            std::string path = root_it->second;
            if (event->len > 0) {
                path += '/';
                path += event->name;
            }

            if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
                if (event->mask & IN_ISDIR) {
                    LOG(INFO) << "ignoring new directory at '" << path << "'";
                } else {
                    LOG(INFO) << "observed new file at '" << path << "'";
                    read_keys(path, false);
                }
            } else {
                LOG(WARNING) << "unmonitored event for " << path << ": 0x" << std::hex
                             << event->mask;
            }

            start += sizeof(struct inotify_event) + event->len;
        }
    }
}

static void adb_auth_inotify_init(const std::set<std::string>& paths) {
    LOG(INFO) << "adb_auth_inotify_init...";
    int infd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    for (const std::string& path : paths) {
        int wd = inotify_add_watch(infd, path.c_str(), IN_CREATE | IN_MOVED_TO);
        if (wd < 0) {
            PLOG(ERROR) << "failed to inotify_add_watch on path '" << path;
            continue;
        }

        g_monitored_paths[wd] = path;
        LOG(INFO) << "watch descriptor " << wd << " registered for " << path;
    }

    fdevent* event = fdevent_create(infd, adb_auth_inotify_update, nullptr);
    fdevent_add(event, FDE_READ);
}
#endif

void adb_auth_init() {
   // LOG(INFO) << "adb_auth_init...";

    if (!get_user_key()) {
        //LOG(ERROR) << "Failed to get user key";
        return;
    }

    const auto& key_paths = get_vendor_keys();

#if defined(__linux__)
    adb_auth_inotify_init(key_paths);
#endif

    for (const std::string& path : key_paths) {
        read_keys(path.c_str());
    }
}

static void send_auth_publickey(atransport* t) {
    //LOG(INFO) << "Calling send_auth_publickey";

    std::string key = adb_auth_get_userkey();
    if (key.empty()) {
        D("Failed to get user public key");
        return;
    }

    if (key.size() >= MAX_PAYLOAD_V1) {
        D("User public key too large (%zu B)", key.size());
        return;
    }

    apacket* p = get_apacket();
    memcpy(p->data, key.c_str(), key.size() + 1);

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_RSAPUBLICKEY;

    // adbd expects a null-terminated string.
    p->msg.data_length = key.size() + 1;
    send_packet(p, t);
}

void send_auth_response(const char* token, size_t token_size, atransport* t) {
    std::shared_ptr<RSA> key = t->NextKey();
    if (key == nullptr) {
        // No more private keys to try, send the public key.
        send_auth_publickey(t);
        return;
    }

    //LOG(INFO) << "Calling send_auth_response";
    apacket* p = get_apacket();

    int ret = adb_auth_sign(key.get(), token, token_size, p->data);
    if (!ret) {
        D("Error signing the token");
        put_apacket(p);
        return;
    }

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_SIGNATURE;
    p->msg.data_length = ret;
    send_packet(p, t);
}
