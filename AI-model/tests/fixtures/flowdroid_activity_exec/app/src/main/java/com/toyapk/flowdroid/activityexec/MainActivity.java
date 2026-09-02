package com.toyapk.flowdroid.activityexec;

import android.app.Activity;
import android.os.Bundle;

import java.io.IOException;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String attackerControlledCommand = getIntent().getStringExtra("cmd");
        forward(attackerControlledCommand);
    }

    private void forward(String command) {
        execute(command);
    }

    private void execute(String command) {
        if (command == null) {
            return;
        }
        try {
            Runtime.getRuntime().exec(command);
        } catch (IOException ignored) {
            // Toy evidence path only: runtime behavior is outside this static-analysis fixture.
        }
    }
}
