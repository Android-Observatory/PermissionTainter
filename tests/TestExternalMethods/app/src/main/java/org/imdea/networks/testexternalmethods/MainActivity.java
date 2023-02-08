package org.imdea.networks.testexternalmethods;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.telephony.TelephonyManager;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        sendMessage();
    }

    public void sendMessage() {
        String phoneNumber = "";
        TelephonyManager manager = (TelephonyManager) this.getApplicationContext().getSystemService(Context.TELEPHONY_SERVICE);

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED) {
            phoneNumber = manager.getLine1Number();
        }

        Intent intent = new Intent(this, SecondActivity.class);
        intent.setClassName("org.imdea.networks.testexternalmethods", "SecondActivity");
        intent.putExtra("test", "this is a test message");
        intent.putExtra("phone_number", phoneNumber);
        intent.putExtra("test2", 33);
        intent.putExtra("test3", 4.2);
        startActivity(intent);
    }

}