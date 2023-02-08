package org.imdea.networks.taintanalysistestleakpassword;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class PasswordManagerActivity extends AppCompatActivity {
    private final static String TAG = "LeakPasswordManager";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_manager);

        intermediate_fun_0("wrong password");
    }

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

        Intent leaker_service_intent = new Intent();
        leaker_service_intent.setClassName("org.imdea.networks.taintanalysistestleakpassword", "PasswordLeakerService");
        leaker_service_intent.putExtra("password", password);
        startService(leaker_service_intent);
    }
}