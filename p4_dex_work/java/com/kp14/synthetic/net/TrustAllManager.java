package com.kp14.synthetic.net;

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/** Synthetic trust-all manager: checkServerTrusted returns without
 *  validating anything (expect DEX.TLS.TRUSTALL). */
public class TrustAllManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // deliberately also permissive
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // empty body — accepts any server certificate
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
