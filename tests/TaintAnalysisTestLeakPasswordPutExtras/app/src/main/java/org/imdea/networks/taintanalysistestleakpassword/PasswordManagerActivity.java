package org.imdea.networks.taintanalysistestleakpassword;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;

import java.io.Serializable;

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

        /* Creating all extra values */
        byte byte_value = 'a';
        char char_value = 'a';
        short short_value = 0;
        int int_value = 0;
        float float_value = 0;
        double double_value = 0.0;
        CharSequence charsequence_value = new CharSequence() {
            @Override
            public int length() {
                return 0;
            }

            @Override
            public char charAt(int i) {
                return 0;
            }

            @NonNull
            @Override
            public CharSequence subSequence(int i, int i1) {
                return "0";
            }
        };

        Parcelable parcelable_value = new Parcelable() {
            @Override
            public int describeContents() {
                return 0;
            }

            @Override
            public void writeToParcel(Parcel parcel, int i) {
            }
        };

        Serializable serializable_value = new Serializable() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        };

        /* Add extras */
        leaker_service_intent.putExtra("boolean", true);
        leaker_service_intent.putExtra("byte", byte_value);
        leaker_service_intent.putExtra("char", char_value);
        leaker_service_intent.putExtra("short", short_value);
        leaker_service_intent.putExtra("int", int_value);
        leaker_service_intent.putExtra("float", float_value);
        leaker_service_intent.putExtra("double", double_value);
        leaker_service_intent.putExtra("string", password);
        leaker_service_intent.putExtra("charsequence", charsequence_value);
        leaker_service_intent.putExtra("parcelable", parcelable_value);
        leaker_service_intent.putExtra("serializable", serializable_value);

        /* Add extras (arrays) */
        leaker_service_intent.putExtra("boolean_array", new boolean[]{true, true});
        leaker_service_intent.putExtra("byte_array", new byte[]{byte_value, byte_value});
        leaker_service_intent.putExtra("char_array", new char[]{char_value, char_value});
        leaker_service_intent.putExtra("short_array", new short[]{short_value, short_value});
        leaker_service_intent.putExtra("int_array", new int[]{int_value, int_value});
        leaker_service_intent.putExtra("float_array", new float[]{float_value, float_value});
        leaker_service_intent.putExtra("double_array", new double[]{double_value, double_value});
        leaker_service_intent.putExtra("string_array", new String[]{password, password});
        leaker_service_intent.putExtra("charsequence_array", new CharSequence[]{charsequence_value, charsequence_value});
        leaker_service_intent.putExtra("parcelable_array", new Parcelable[]{parcelable_value, parcelable_value});

        startService(leaker_service_intent);
    }
}