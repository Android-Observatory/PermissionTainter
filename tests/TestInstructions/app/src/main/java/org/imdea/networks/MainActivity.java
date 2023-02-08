package org.imdea.networks;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;


public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        testAritmethicInstructions();
        testBooleanInstructions();
    }

    protected void testAritmethicInstructions(){
        AritmethicInstructions.leakSumInt(getIntPassword());
        AritmethicInstructions.leakSubInt(getIntPassword());
        AritmethicInstructions.leakMulInt(getIntPassword());
        AritmethicInstructions.leakDivInt(getIntPassword());
        AritmethicInstructions.leakRemInt(getIntPassword());

        AritmethicInstructions.leakSumFloat(getFloatPassword());
        AritmethicInstructions.leakSubFloat(getFloatPassword());
        AritmethicInstructions.leakMulFloat(getFloatPassword());
        AritmethicInstructions.leakDivFloat(getFloatPassword());
        AritmethicInstructions.leakRemFloat(getFloatPassword());

        AritmethicInstructions.leakSumShort(getShortPassword());
        AritmethicInstructions.leakSubShort(getShortPassword());
        AritmethicInstructions.leakMulShort(getShortPassword());
        AritmethicInstructions.leakDivShort(getShortPassword());
        AritmethicInstructions.leakRemShort(getShortPassword());
    }

    protected void testBooleanInstructions(){
        BooleanInstructions.leakAndBoolean(getBooleanPassword());
        BooleanInstructions.leakOrBoolean(getBooleanPassword());
        BooleanInstructions.leakXorBoolean(getBooleanPassword());

        BooleanInstructions.leakAndLong(getLongPassword());
        BooleanInstructions.leakOrLong(getLongPassword());
        BooleanInstructions.leakXorLong(getLongPassword());

        BooleanInstructions.leakAndShort(getShortPassword());
        BooleanInstructions.leakOrShort(getShortPassword());
        BooleanInstructions.leakXorShort(getShortPassword());

        BooleanInstructions.leakAndByte(getBytePassword());
        BooleanInstructions.leakOrByte(getBytePassword());
        BooleanInstructions.leakXorByte(getBytePassword());
    }


    
    protected int getIntPassword(){
        return 10;
    }

    protected float getFloatPassword(){
        return (float) 1;
    }

    protected short getShortPassword(){
        return (short) 1;
    }

    protected boolean getBooleanPassword() {return true;}

    protected long getLongPassword() {return (long) 1;}

    protected byte getBytePassword() {return (byte) 1;}

}