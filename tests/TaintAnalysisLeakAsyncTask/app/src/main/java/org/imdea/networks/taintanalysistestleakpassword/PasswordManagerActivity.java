package org.imdea.networks.taintanalysistestleakpassword;

import android.util.Log;

public class PasswordManagerActivity {

    private final static String TAG = "LeakPasswordManager";

    public static String get_password() {
        Log.i(TAG, "get_password");
        return "password";
    }

}