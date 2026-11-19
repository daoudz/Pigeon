package com.pigeon.voice.ui;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.pigeon.voice.R;
import com.pigeon.voice.contacts.ContactItem;
import com.pigeon.voice.contacts.ContactsRepository;
import com.pigeon.voice.net.ActiveSessionRegistry;
import com.pigeon.voice.net.NetworkUtils;
import com.pigeon.voice.net.P2PSessionManager;
import com.pigeon.voice.token.InviteToken;

import java.util.ArrayList;
import java.util.List;

/**
 * Main Dashboard Activity for Pigeon Serverless P2P Voice, Chat & Image App.
 *
 * Allows any device to:
 * 1. Choose a contact to call (from Android Contacts or saved Pigeon Contacts)
 * 2. Act as the encrypted Call Server (generating a one-time token & pigeon:// deep link)
 * 3. Join another device's call server directly via token or deep link without any intermediary server
 */
public final class MainActivity extends AppCompatActivity {

    private static final int REQ_PERMISSIONS = 1001;

    private ContactsRepository contactsRepository;
    private ContactItem selectedContact = null;

    private TextView tvLocalEndpoints;
    private EditText etDisplayName;
    private EditText etUserPhone;
    private TextView tvSelectedContact;
    private SwitchCompat switchLockToContact;
    private EditText etJoinToken;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        contactsRepository = new ContactsRepository(this);

        tvLocalEndpoints = findViewById(R.id.tvLocalEndpoints);
        etDisplayName = findViewById(R.id.etDisplayName);
        etUserPhone = findViewById(R.id.etUserPhone);
        tvSelectedContact = findViewById(R.id.tvSelectedContact);
        switchLockToContact = findViewById(R.id.switchLockToContact);
        etJoinToken = findViewById(R.id.etJoinToken);

        Button btnChooseContact = findViewById(R.id.btnChooseContact);
        Button btnAddContact = findViewById(R.id.btnAddContact);
        Button btnHostCall = findViewById(R.id.btnHostCall);
        Button btnPasteToken = findViewById(R.id.btnPasteToken);
        Button btnJoinCall = findViewById(R.id.btnJoinCall);

        etDisplayName.setText(contactsRepository.getLocalUserName());
        etUserPhone.setText(contactsRepository.getLocalUserPhoneOrHandle());
        refreshLocalEndpointsBanner();

        btnChooseContact.setOnClickListener(v -> showChooseContactDialog());
        btnAddContact.setOnClickListener(v -> showAddContactDialog());
        btnHostCall.setOnClickListener(v -> startHostingCall());
        btnPasteToken.setOnClickListener(v -> pasteTokenFromClipboard());
        btnJoinCall.setOnClickListener(v -> joinCallFromInput());

        requestRequiredPermissionsIfNeeded();
        handleIncomingDeepLink(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIncomingDeepLink(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshLocalEndpointsBanner();
    }

    private void refreshLocalEndpointsBanner() {
        List<String> ips = NetworkUtils.getCandidateHostAddresses(null);
        String joined = TextUtils.join(", ", ips);
        tvLocalEndpoints.setText("Serverless P2P & 5G Ready • IP(s): " + joined);
    }

    private void handleIncomingDeepLink(Intent intent) {
        if (intent == null) {
            return;
        }
        String action = intent.getAction();
        Uri data = intent.getData();
        if (Intent.ACTION_VIEW.equals(action) && data != null) {
            String rawUri = data.toString();
            etJoinToken.setText(rawUri);
            try {
                InviteToken token = InviteToken.fromTokenOrLink(rawUri);
                Toast.makeText(
                        this,
                        "Loaded call invite from " + token.getHostDisplayName(),
                        Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(this, "Invalid call link: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        } else if (Intent.ACTION_SEND.equals(action) && "text/plain".equals(intent.getType())) {
            String sharedText = intent.getStringExtra(Intent.EXTRA_TEXT);
            if (sharedText != null && !sharedText.trim().isEmpty()) {
                etJoinToken.setText(sharedText.trim());
            }
        }
    }

    private void saveUserProfileFromInputs() {
        String name = etDisplayName.getText().toString().trim();
        String phone = etUserPhone.getText().toString().trim();
        if (name.isEmpty()) {
            name = "Pigeon Peer";
            etDisplayName.setText(name);
        }
        contactsRepository.saveLocalUserProfile(name, phone);
    }

    private void showChooseContactDialog() {
        List<ContactItem> contacts = contactsRepository.loadAllContacts(null);
        List<String> labels = new ArrayList<>();
        labels.add("Open 1-on-1 Call (Any holder of one-time token)");
        for (ContactItem c : contacts) {
            String tag = c.isSystemContact() ? " [Device]" : " [Pigeon]";
            labels.add(c.getName() + " • " + c.getPhoneOrHandle() + tag);
        }

        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                this,
                android.R.layout.simple_list_item_1,
                labels);

        new AlertDialog.Builder(this)
                .setTitle("Choose Contact to Call")
                .setAdapter(adapter, (dialog, which) -> {
                    if (which == 0) {
                        selectedContact = null;
                        tvSelectedContact.setText("Selected Contact: Any Token Holder (Open 1-on-1)");
                        switchLockToContact.setChecked(false);
                    } else {
                        selectedContact = contacts.get(which - 1);
                        tvSelectedContact.setText("Calling: " + selectedContact.getName()
                                + " (" + selectedContact.getPhoneOrHandle() + ")");
                        switchLockToContact.setChecked(true);
                    }
                })
                .setNeutralButton("+ New Contact", (d, w) -> showAddContactDialog())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showAddContactDialog() {
        LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (18 * getResources().getDisplayMetrics().density);
        container.setPadding(pad, pad, pad, 0);

        EditText etName = new EditText(this);
        etName.setHint("Contact Name (e.g. Alice)");
        container.addView(etName);

        EditText etPhone = new EditText(this);
        etPhone.setHint("Phone Number or Handle (e.g. +15551234567)");
        container.addView(etPhone);

        new AlertDialog.Builder(this)
                .setTitle("Add Contact")
                .setView(container)
                .setPositiveButton("Save & Select", (dialog, which) -> {
                    String name = etName.getText().toString().trim();
                    String phone = etPhone.getText().toString().trim();
                    if (name.isEmpty() || phone.isEmpty()) {
                        Toast.makeText(this, "Name and phone/handle are required", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    selectedContact = contactsRepository.addCustomContact(name, phone);
                    tvSelectedContact.setText("Calling: " + selectedContact.getName()
                            + " (" + selectedContact.getPhoneOrHandle() + ")");
                    switchLockToContact.setChecked(true);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void startHostingCall() {
        if (!hasAudioPermission()) {
            requestRequiredPermissionsIfNeeded();
            Toast.makeText(this, "Microphone permission is required for voice calls", Toast.LENGTH_LONG).show();
            return;
        }

        saveUserProfileFromInputs();
        String hostName = contactsRepository.getLocalUserName();
        String allowedContactHash = "";

        if (switchLockToContact.isChecked()) {
            if (selectedContact == null) {
                Toast.makeText(
                        this,
                        "Select a contact first or disable 'Lock invite to selected contact'",
                        Toast.LENGTH_LONG).show();
                return;
            }
            allowedContactHash = selectedContact.getContactHash();
        }

        try {
            P2PSessionManager session = new P2PSessionManager();
            session.startHosting(hostName, allowedContactHash);
            ActiveSessionRegistry.setActiveSession(session);

            Intent callIntent = new Intent(this, CallActivity.class);
            if (selectedContact != null) {
                callIntent.putExtra(CallActivity.EXTRA_CONTACT_NAME, selectedContact.getName());
                callIntent.putExtra(CallActivity.EXTRA_CONTACT_PHONE, selectedContact.getPhoneOrHandle());
            }
            startActivity(callIntent);
        } catch (Exception e) {
            Toast.makeText(this, "Failed to start call server: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void pasteTokenFromClipboard() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null && cm.hasPrimaryClip()) {
            ClipData clip = cm.getPrimaryClip();
            if (clip != null && clip.getItemCount() > 0) {
                CharSequence text = clip.getItemAt(0).coerceToText(this);
                if (text != null) {
                    etJoinToken.setText(text.toString().trim());
                    return;
                }
            }
        }
        Toast.makeText(this, "Clipboard is empty", Toast.LENGTH_SHORT).show();
    }

    private void joinCallFromInput() {
        if (!hasAudioPermission()) {
            requestRequiredPermissionsIfNeeded();
            Toast.makeText(this, "Microphone permission is required for voice calls", Toast.LENGTH_LONG).show();
            return;
        }

        saveUserProfileFromInputs();
        String rawInput = etJoinToken.getText().toString().trim();
        if (rawInput.isEmpty()) {
            Toast.makeText(this, "Please paste an invite link or token first", Toast.LENGTH_SHORT).show();
            return;
        }

        InviteToken token;
        try {
            token = InviteToken.fromTokenOrLink(rawInput);
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, "Invalid token: " + e.getMessage(), Toast.LENGTH_LONG).show();
            return;
        }

        if (token.isExpired(System.currentTimeMillis())) {
            Toast.makeText(this, "This invite token has expired.", Toast.LENGTH_LONG).show();
            return;
        }

        String myName = contactsRepository.getLocalUserName();
        String myPhone = contactsRepository.getLocalUserPhoneOrHandle();
        String myContactHash = ContactItem.computeContactHash(myPhone);

        if (token.isContactRestricted() && !token.isContactPermitted(myContactHash)) {
            Toast.makeText(
                    this,
                    "This call is locked to a specific contact. Ensure 'Your Phone or Handle' matches the invited contact.",
                    Toast.LENGTH_LONG).show();
            etUserPhone.requestFocus();
            return;
        }

        P2PSessionManager session = new P2PSessionManager();
        ActiveSessionRegistry.setActiveSession(session);
        session.joinSession(token, myName, myPhone);

        Intent callIntent = new Intent(this, CallActivity.class);
        startActivity(callIntent);
    }

    private boolean hasAudioPermission() {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void requestRequiredPermissionsIfNeeded() {
        List<String> needed = new ArrayList<>();
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
                != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.RECORD_AUDIO);
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CONTACTS)
                != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.READ_CONTACTS);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                needed.add(Manifest.permission.POST_NOTIFICATIONS);
            }
        }
        if (!needed.isEmpty()) {
            ActivityCompat.requestPermissions(
                    this,
                    needed.toArray(new String[0]),
                    REQ_PERMISSIONS);
        }
    }

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            @NonNull String[] permissions,
            @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }
}
