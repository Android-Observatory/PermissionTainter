package org.imdea.networks.taintanalysistestleakpassword;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcelable;
import android.util.Log;

public class PasswordLeakerService extends Service {
    private final static String TAG = "LeakPasswordLeaker";

    public PasswordLeakerService() {
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Bundle extras = intent.getExtras();
        String password = extras.getString("string");

        intent.getBooleanExtra("boolean", true);
        intent.getByteExtra("byte", (byte)'a');
        intent.getCharExtra("char", 'a');
        intent.getShortExtra("short", (short)0);
        intent.getIntExtra("int", 0);
        intent.getFloatExtra("float", (float)0.0);
        intent.getDoubleExtra("double", 0.0);
        intent.getStringExtra("string");
        intent.getCharSequenceExtra("charsequence");
        intent.getParcelableExtra("parcelable");
        intent.getSerializableExtra("serializable");


        /* Add extras (arrays) */
        intent.getBooleanArrayExtra("boolean_array");
        intent.getByteArrayExtra("byte_array");
        intent.getCharArrayExtra("char_array");
        intent.getShortArrayExtra("short_array");
        intent.getIntArrayExtra("int_array");
        intent.getFloatArrayExtra("float_array");
        intent.getDoubleArrayExtra("double_array");
        intent.getStringArrayExtra("string_array");
        intent.getCharSequenceArrayExtra("charsequence_array");
        intent.getParcelableArrayExtra("parcelable_array");

        leak_password(password);

        return super.onStartCommand(intent, flags, startId);
    }

    private void leak_password(String password) {
        Log.i(TAG, "leak_password");
        Log.i(TAG, password);
        Log.i(TAG, "Leaked!");
    }

    @Override
    public IBinder onBind(Intent intent) {
        // TODO: Return the communication channel to the service.
        throw new UnsupportedOperationException("Not yet implemented");
    }
}
