package com.reactlibrary;

import android.annotation.SuppressLint;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.network.OkHttpClientFactory;
import com.facebook.react.modules.network.ReactCookieJarContainer;

import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ConnectionSpec;
import okhttp3.TlsVersion;

public class CustomClientFactory implements OkHttpClientFactory {
    private final String certificateFileP12;
    private final String certificatePassword;

    public CustomClientFactory(String certificateFileP12, String certificatePassword) {
        this.certificateFileP12 = certificateFileP12;
        this.certificatePassword = certificatePassword;
    }

    @Override
    public OkHttpClient createNewNetworkModuleClient() {
        String TAG = "OkHttpClientFactory";

        try {
            // Load the client certificate
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            byte[] decbytes = Base64.decode(certificateFileP12, Base64.DEFAULT);
            try (InputStream stream = new ByteArrayInputStream(decbytes)) {
                keyStore.load(stream, certificatePassword.toCharArray());
            }

            // Set up key manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, certificatePassword.toCharArray());

            // Set up trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null); // Use the default trust store
            X509TrustManager trustManager = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];

            // Set up SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            // Build OkHttpClient
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                    .cookieJar(new ReactCookieJarContainer());

            // Enable TLS v1.3 and v1.2
            ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                    .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
                    .build();

            builder.connectionSpecs(Arrays.asList(spec, ConnectionSpec.COMPATIBLE_TLS));

            builder.addInterceptor(new CustomInterceptor());

            return builder.build();

        } catch (Exception e) {
            Log.e(TAG, "Error creating OkHttpClient: " + e.getMessage());
            throw new RuntimeException("Failed to create OkHttpClient", e);
        }
    }

    private static class CustomInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request originalRequest = chain.request();

            // Log request headers
            Map<String, String> uppercaseHeaders = convertHeadersToUppercase(originalRequest.headers());

            okhttp3.Headers.Builder headersBuilder = new okhttp3.Headers.Builder();
            for (Map.Entry<String, String> entry : uppercaseHeaders.entrySet()) {
                headersBuilder.add(entry.getKey(), entry.getValue());
            }

            Request newRequest = originalRequest.newBuilder()
                    .headers(headersBuilder.build())
                    .build();

            Response response = chain.proceed(newRequest);

            return response;
        }

        private Map<String, String> convertHeadersToUppercase(okhttp3.Headers headers) {
            Map<String, String> uppercaseHeaders = new HashMap<>();
            for (int i = 0, size = headers.size(); i < size; i++) {
                String key = headers.name(i).toUpperCase();
                String value = headers.value(i);
                uppercaseHeaders.put(key, value);
            }
            return uppercaseHeaders;
        }
    }
}
