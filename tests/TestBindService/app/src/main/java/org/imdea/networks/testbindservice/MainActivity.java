package org.imdea.networks.testbindservice;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.IBinder;
import android.telephony.TelephonyManager;
import android.util.Log;

public class MainActivity extends AppCompatActivity {
    RegularService mService;
    boolean mBound = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        Intent intent = new Intent(this, RegularService.class);
        intent.setClassName("org.imdea.networks.testbindservice", "RegularService");
        intent.putExtra("test", "this is a test message");
        intent.putExtra("password", get_amazing_password());
        intent.putExtra("test2", 33);
        intent.putExtra("test3", 4.2);
        bindService(intent, connection, Context.BIND_AUTO_CREATE);
        mService.leakGlobalPassword();
    }

    private ServiceConnection connection = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName className,
                                       IBinder service) {
            // We've bound to LocalService, cast the IBinder and get LocalService instance
            RegularService.LocalBinder binder = (RegularService.LocalBinder) service;
            mService = binder.getService();
            mBound = true;
        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            mBound = false;
        }
    };


    private String get_amazing_password()
    {
        return "An amazing password";
    }
}