package org.imdea.networks.taintanalysistestleakpassword;

import androidx.appcompat.app.AppCompatActivity;

import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;


public class MainActivity extends AppCompatActivity {

    String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String password = PasswordManagerActivity.get_password();
        new LeakPasswordTask().execute(password);

    }

    private class LeakPasswordTask extends AsyncTask<String, Integer, String>{

        @Override
        protected void onPreExecute() {
            Log.i(TAG, "not a leak");
            super.onPreExecute();
        }

        @Override
        protected String doInBackground(String... passwords) {
            int count = passwords.length;
            for (int i = 0; i < count; i++) {
                publishProgress((int) ((i / (float) count) * 100));
                // Escape early if cancel() is called
                if (isCancelled()) break;
                Log.i(TAG, "not a leak");
            }

            return passwords[0];
        }

        @Override
        protected void onProgressUpdate(Integer... progress) {
            Log.i(TAG, "Ongoing...");
        }

        @Override
        protected void onPostExecute(String password){
            Log.i(TAG, password);
            Log.i(TAG, "Password leaked");
        }
    }
}