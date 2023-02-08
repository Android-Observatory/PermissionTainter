package org.imdea.networks;

import android.util.Log;

public class BooleanInstructions {
    private static String TAG = "BooleanInstructions";

    protected static void leakAndBoolean (boolean passwd){
        boolean x = passwd & true;
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakOrBoolean (boolean passwd){
        boolean x = passwd | true;
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakXorBoolean (boolean passwd){
        boolean x = passwd ^ true;
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakAndLong (long passwd){
        long x = passwd & (long) 1;
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakOrLong (long passwd){
        long x = passwd | (long) 1;
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakXorLong (long passwd){
        long x = passwd ^ (long) 1;
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakAndShort (short passwd){
        short x = (short) (passwd & (short) 1);
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakOrShort (short passwd){
        short x = (short) (passwd | (short) 1);
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakXorShort (short passwd){
        short x = (short) (passwd ^ (short) 1.0);
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakAndByte (byte passwd){
        byte x = (byte) (passwd & (byte) 1);
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakOrByte (byte passwd){
        byte x = (byte) (passwd | (byte) 1);
        Log.i(TAG, String.valueOf(x));
    }

    protected static void leakXorByte (byte passwd){
        byte x = (byte) (passwd ^ (byte) 1.0);
        Log.i(TAG, String.valueOf(x));
    }

}
