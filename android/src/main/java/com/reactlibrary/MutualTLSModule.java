package com.reactlibrary;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.modules.network.OkHttpClientProvider;

public class MutualTLSModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;

    public MutualTLSModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "MutualTLS";
    }

    @ReactMethod
    public void configure(ReadableMap readableMap) {
            String certificateFileP12 = readableMap.getString("certificateFileP12");
            String certificatePassword = readableMap.getString("certificatePassword");
            //CustomClientFactory factory = new CustomClientFactory(certificateFileP12, certificatePassword);
            //OkHttpClientProvider.setOkHttpClientFactory(factory);
    }


    @ReactMethod
    public void sampleMethod(String stringArgument, int numberArgument, Callback callback) {
        // TODO: Implement some actually useful functionality
        callback.invoke("Received numberArgument: " + numberArgument + " stringArgument: " + stringArgument);
    }
}
