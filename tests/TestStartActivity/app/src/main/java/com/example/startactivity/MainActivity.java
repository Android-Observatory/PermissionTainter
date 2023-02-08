package com.example.startactivity;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        sendMessage();
    }

    public void sendMessage()
    {
        Intent intent = new Intent(this, SecondActivity.class);
        intent.setClassName("com.example.startactivity", "SecondActivity");
        intent.putExtra("test", "this is a test message");
        intent.putExtra("password", get_amazing_password());
        intent.putExtra("test2", 33);
        intent.putExtra("test3", 4.2);
        startActivity(intent);
    }

    private String get_amazing_password()
    {
        return "An amazing password";
    }
}