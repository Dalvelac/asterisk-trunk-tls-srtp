FROM andrius/asterisk:22.8-cert5_debian-trixie@sha256:2c66ecf8508820e9c856d24a20ec4d123399526cfe6fe8da66dca90e3961f092

# Both PBXs run these exact Asterisk binaries. Add a capture tool for eth0.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump \
 && rm -rf /var/lib/apt/lists/* \
 && test "$(asterisk -V)" = "Asterisk certified-22.8-cert5" \
 && for module in chan_pjsip res_pjsip res_pjsip_sdp_rtp res_srtp; do \
        test -s "/usr/lib/asterisk/modules/$module.so" || exit 1; \
    done

COPY start /usr/local/bin/start-pbx
ENTRYPOINT ["/bin/sh", "/usr/local/bin/start-pbx"]
CMD []
