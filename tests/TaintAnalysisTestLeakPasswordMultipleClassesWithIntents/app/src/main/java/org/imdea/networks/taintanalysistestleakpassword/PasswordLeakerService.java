package org.imdea.networks.taintanalysistestleakpassword;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

public class PasswordLeakerService extends Service {
    private final static String TAG = "LeakPasswordLeaker";

    public PasswordLeakerService() {
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Bundle extras = intent.getExtras();
        String password = extras.getString("password");
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
