package org.imdea.networks;

import android.util.Log;

public class AritmethicInstructions {

    private static final String TAG = "MainActivity";
    
    public static int addInt(int x){
        return x + 1;
    }

    public static int subInt(int x){
        return x - 1;
    }

    public static int mulInt(int x){
        return x * 1;
    }

    public static int divInt(int x){
        return x / 1;
    }

    public static int remInt(int x){
        return x % 1;
    }

    public static float addFloat(float x){
        return x + 1;
    }

    public static float subFloat(float x){
        return x - 1;
    }

    public static float mulFloat(float x){
        return x * 1;
    }

    public static float divFloat(float x){
        return x / 1;
    }

    public static float remFloat(float x){
        return x % 1;
    }

    public static short addShort(short x){
        return (short) (x + (short) 1);
    }

    public static short subShort(short x){
        return (short) (x - (short) 1);
    }

    public static short mulShort(short x){
        return (short) (x * (short) 1);
    }

    public static short divShort(short x){
        return (short) (x / (short) 1);
    }

    public static short remShort(short x){
        return (short) (x % (short) 1);
    }

    protected static void leakSumInt(int passwd) {
        int a = AritmethicInstructions.addInt(passwd);
        Log.i(TAG, String.valueOf(a));
    }
    protected static void leakSubInt(int passwd){
        int b = AritmethicInstructions.subInt(passwd);
        Log.i(TAG, String.valueOf(b));
    }

    protected static void leakMulInt(int passwd) {
        int c = AritmethicInstructions.mulInt(passwd);
        Log.i(TAG, String.valueOf(c));
    }

    protected static void leakDivInt(int passwd){
        int d = AritmethicInstructions.divInt(passwd);
        Log.i(TAG, String.valueOf(d));
    }
    protected static void leakRemInt(int passwd) {
        int e = AritmethicInstructions.remInt(passwd);
        Log.i(TAG, String.valueOf(e));
    }

    protected static void leakSumFloat(float passwd) {
        float a = AritmethicInstructions.addFloat(passwd);
        Log.i(TAG, String.valueOf(a));
    }
    protected static void leakSubFloat(float passwd){
        float b = AritmethicInstructions.subFloat(passwd);
        Log.i(TAG, String.valueOf(b));
    }

    protected static void leakMulFloat(float passwd) {
        float c = AritmethicInstructions.mulFloat(passwd);
        Log.i(TAG, String.valueOf(c));
    }

    protected static void leakDivFloat(float passwd){
        float d = AritmethicInstructions.divFloat(passwd);
        Log.i(TAG, String.valueOf(d));
    }
    protected static void leakRemFloat(float passwd) {
        float e = AritmethicInstructions.remFloat(passwd);
        Log.i(TAG, String.valueOf(e));
    }

    protected static void leakSumShort(short passwd) {
        short a = AritmethicInstructions.addShort(passwd);
        Log.i(TAG, String.valueOf(a));
    }
    protected static void leakSubShort(short passwd){
        short b = AritmethicInstructions.subShort(passwd);
        Log.i(TAG, String.valueOf(b));
    }

    protected static void leakMulShort(short passwd) {
        short c = AritmethicInstructions.mulShort(passwd);
        Log.i(TAG, String.valueOf(c));
    }

    protected static void leakDivShort(short passwd){
        short d = AritmethicInstructions.divShort(passwd);
        Log.i(TAG, String.valueOf(d));
    }
    protected static void leakRemShort(short passwd) {
        short e = AritmethicInstructions.remShort(passwd);
        Log.i(TAG, String.valueOf(e));
    }


}
