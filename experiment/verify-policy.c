/* Optional Linux diagnostic. Log public policy parameters only after libSRTP
 * successfully installs a stream. No SDP, packet contents or keys are read. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <srtp2/srtp.h>
#include <srtp2/crypto_types.h>

static void *library_function(const char *name)
{
    void *library = dlopen("libsrtp2.so.1", RTLD_NOW | RTLD_NOLOAD);
    void *function = library ? dlsym(library, name) : NULL;
    if (!function) {
        fputs("LAB-POLICY: libSRTP symbol unavailable\n", stderr);
        abort();
    }
    /* Keep the handle for the lifetime of this short diagnostic process. */
    return function;
}

static void record_policy(const srtp_policy_t *policy, srtp_err_status_t status)
{
    if (!policy || status != srtp_err_status_ok)
        return;
    const srtp_crypto_policy_t *rtp = &policy->rtp;
    int matches = rtp->cipher_type == SRTP_AES_ICM_128 &&
                  rtp->auth_type == SRTP_HMAC_SHA1 &&
                  rtp->auth_tag_len == 10 && rtp->sec_serv == sec_serv_conf_and_auth;
    fprintf(stderr, "LAB-POLICY RTP cipher_id=%u auth_id=%u tag_bytes=%d services=%d profile=%s\n",
            rtp->cipher_type, rtp->auth_type, rtp->auth_tag_len, rtp->sec_serv,
            matches ? "AES_CM_128_HMAC_SHA1_80" : "other");
}

srtp_err_status_t srtp_create(srtp_t *session, const srtp_policy_t *policy)
{
    srtp_err_status_t (*fn)(srtp_t *, const srtp_policy_t *) = library_function("srtp_create");
    srtp_err_status_t status = fn(session, policy);
    record_policy(policy, status);
    return status;
}

srtp_err_status_t srtp_add_stream(srtp_t session, const srtp_policy_t *policy)
{
    srtp_err_status_t (*fn)(srtp_t, const srtp_policy_t *) = library_function("srtp_add_stream");
    srtp_err_status_t status = fn(session, policy);
    record_policy(policy, status);
    return status;
}
