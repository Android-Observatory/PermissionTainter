package org.imdea.networks.taintanalysistestleakpassword;

import android.util.Log;

public class PasswordLeaker {
    private final static String TAG = "LeakPasswordLeaker";

    public static void leak_password(String password) {
        Log.i(TAG, "leak_password");
        Log.i(TAG, password);
        Log.i(TAG, "Leaked!");
    }
}
