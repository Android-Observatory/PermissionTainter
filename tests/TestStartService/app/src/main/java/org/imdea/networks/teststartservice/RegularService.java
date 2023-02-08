package org.imdea.networks.teststartservice;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;
import android.widget.TextView;

public class RegularService extends Service {
    private final IBinder binder = new LocalBinder();
    private String pass;

    public class LocalBinder extends Binder {
        RegularService getService() {
            // Return this instance of LocalService so clients can call public methods
            return RegularService.this;
        }
    }

    public RegularService() {
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        pass = intent.getStringExtra("password");
        leakPassword(pass);

        return super.onStartCommand(intent, flags, startId);
    }

    public void leakPassword(String pass) {
        Log.e("TAG", pass);
    }

    public void leakGlobalPassword() {
        Log.e("TAG", pass);
    }
}
