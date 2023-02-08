package org.imdea.networks.taintanalysistestleakpassword;

import android.util.Log;

public class PasswordManager {
    private final static String TAG = "LeakPasswordManager";

    public String get_password() {
        Log.i(TAG, "get_password");

        return "password";
    }

    public void intermediate_fun_0(String password) {
        String good_password = get_password();
        if (password.equals(good_password)) {
            intermediate_fun_1(good_password);
        }
    }

    public void intermediate_fun_1(String password) {
        Log.i(TAG, "intermediate_fun_1");

        intermediate_fun_2(password);
    }

    public void intermediate_fun_2(String password) {
        Log.i(TAG, "intermediate_fun_2");

        leak_password(password);
    }

    public void leak_password(String password) {
        Log.i(TAG, "leak_password");
        Log.i(TAG, password);
        Log.i(TAG, "Leaked!");
    }
}