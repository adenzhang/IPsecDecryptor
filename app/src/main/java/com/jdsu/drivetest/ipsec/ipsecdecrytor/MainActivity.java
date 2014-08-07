package com.jdsu.drivetest.ipsec.ipsecdecrytor;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.jdsu.drivetest.packet.SimplePcapReader;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;


public class MainActivity extends Activity {

    void test() {
        Toast.makeText(this, "JDSU ESP Decrytor Running!", Toast.LENGTH_SHORT).show();
//        SimplePcapReader.test_readPcap_DecryptESP();
//        SimplePcapReader.test_pcap_esp_sa();
    }

    EditText txtSaFile;
    EditText txtPcapFile;
    EditText txtSkip;
    EditText txtCount;
    TextView txtOutput;
    Button btnDecrypt;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        txtSaFile = (EditText)findViewById(R.id.txtSA);
        txtPcapFile = (EditText)findViewById(R.id.txtPcap);
        txtSkip = (EditText)findViewById(R.id.txtSkip);
        txtCount = (EditText)findViewById(R.id.txtCount);
        txtOutput = (TextView) findViewById(R.id.txtOutput);

        btnDecrypt = (Button) findViewById(R.id.btnDecrypt);

        txtOutput.setMovementMethod(new ScrollingMovementMethod());
        btnDecrypt.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                String sp  = txtSkip.getText().toString();
                String sn  = txtCount.getText().toString();
                int p = 0, n = 1;
                try {
                    p = Integer.parseInt(sp);
                    n = Integer.parseInt(sn);
                }catch (NumberFormatException e) {

                }

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                PrintStream out = new PrintStream(baos);
                SimplePcapReader.decryptPcap(out, txtSaFile.getText().toString(), txtPcapFile.getText().toString() , p, n);
                String content = baos.toString();
                txtOutput.setText(content);
            }
        });

    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
