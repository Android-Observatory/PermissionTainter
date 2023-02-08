package org.imdea.networks.testbindservice;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

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
        Bundle extras = intent.getExtras();
        pass = extras.getString("password");
        return binder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return super.onStartCommand(intent, flags, startId);
    }

    public void leakGlobalPassword() {
        Log.e("TAG", pass);
    }
}
