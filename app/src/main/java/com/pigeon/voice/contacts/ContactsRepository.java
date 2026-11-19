package com.pigeon.voice.contacts;

import android.Manifest;
import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.provider.ContactsContract;

import androidx.core.content.ContextCompat;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Repository for reading Android device contacts and managing saved Pigeon contacts.
 */
public final class ContactsRepository {

    private static final String PREFS_NAME = "pigeon_contacts_prefs";
    private static final String KEY_CUSTOM_CONTACTS = "custom_contacts_json";
    private static final String KEY_LOCAL_USER_NAME = "local_user_name";
    private static final String KEY_LOCAL_USER_PHONE = "local_user_phone";

    private final Context context;
    private final SharedPreferences prefs;

    public ContactsRepository(Context context) {
        this.context = context.getApplicationContext();
        this.prefs = this.context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public String getLocalUserName() {
        String name = prefs.getString(KEY_LOCAL_USER_NAME, "");
        if (name == null || name.trim().isEmpty()) {
            return android.os.Build.MODEL != null ? android.os.Build.MODEL : "Pigeon User";
        }
        return name.trim();
    }

    public String getLocalUserPhoneOrHandle() {
        String phone = prefs.getString(KEY_LOCAL_USER_PHONE, "");
        return phone == null ? "" : phone.trim();
    }

    public void saveLocalUserProfile(String displayName, String phoneOrHandle) {
        prefs.edit()
                .putString(KEY_LOCAL_USER_NAME, displayName == null ? "" : displayName.trim())
                .putString(KEY_LOCAL_USER_PHONE, phoneOrHandle == null ? "" : phoneOrHandle.trim())
                .apply();
    }

    public List<ContactItem> loadAllContacts(String searchQuery) {
        List<ContactItem> combined = new ArrayList<>();
        Set<String> seenHashes = new HashSet<>();

        // 1. Load custom contacts saved in Pigeon
        List<ContactItem> customList = loadCustomContacts();
        for (ContactItem item : customList) {
            String h = item.getContactHash();
            if (!h.isEmpty()) {
                seenHashes.add(h);
            }
            combined.add(item);
        }

        // 2. Load Android device contacts if permission is granted
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CONTACTS)
                == PackageManager.PERMISSION_GRANTED) {
            List<ContactItem> systemContacts = querySystemContacts();
            for (ContactItem sys : systemContacts) {
                String h = sys.getContactHash();
                if (!h.isEmpty() && seenHashes.contains(h)) {
                    continue;
                }
                seenHashes.add(h);
                combined.add(sys);
            }
        }

        // 3. Filter by search query if non-empty
        if (searchQuery != null && !searchQuery.trim().isEmpty()) {
            String q = searchQuery.trim().toLowerCase(Locale.US);
            List<ContactItem> filtered = new ArrayList<>();
            for (ContactItem item : combined) {
                if (item.getName().toLowerCase(Locale.US).contains(q)
                        || item.getPhoneOrHandle().toLowerCase(Locale.US).contains(q)) {
                    filtered.add(item);
                }
            }
            combined = filtered;
        }

        // Sort alphabetically by name
        Collections.sort(combined, (a, b) -> a.getName().compareToIgnoreCase(b.getName()));
        return combined;
    }

    public ContactItem addCustomContact(String name, String phoneOrHandle) {
        if (name == null || name.trim().isEmpty() || phoneOrHandle == null || phoneOrHandle.trim().isEmpty()) {
            throw new IllegalArgumentException("Contact name and phone/handle are required");
        }
        List<ContactItem> current = loadCustomContacts();
        ContactItem created = new ContactItem(
                UUID.randomUUID().toString(),
                name.trim(),
                phoneOrHandle.trim(),
                false,
                System.currentTimeMillis());

        String targetHash = created.getContactHash();
        List<ContactItem> updated = new ArrayList<>();
        updated.add(created);
        for (ContactItem existing : current) {
            if (!existing.getContactHash().equals(targetHash)) {
                updated.add(existing);
            }
        }
        saveCustomContacts(updated);
        return created;
    }

    public void deleteCustomContact(String contactId) {
        if (contactId == null) {
            return;
        }
        List<ContactItem> current = loadCustomContacts();
        List<ContactItem> updated = new ArrayList<>();
        for (ContactItem existing : current) {
            if (!contactId.equals(existing.getId())) {
                updated.add(existing);
            }
        }
        saveCustomContacts(updated);
    }

    private List<ContactItem> loadCustomContacts() {
        String rawJson = prefs.getString(KEY_CUSTOM_CONTACTS, null);
        List<ContactItem> list = new ArrayList<>();
        if (rawJson == null || rawJson.isEmpty()) {
            return list;
        }
        try {
            JSONArray array = new JSONArray(rawJson);
            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                list.add(new ContactItem(
                        obj.optString("id", UUID.randomUUID().toString()),
                        obj.optString("name", "Contact"),
                        obj.optString("phone", ""),
                        false,
                        obj.optLong("lastCalled", 0L)
                ));
            }
        } catch (Exception ignored) {
        }
        return list;
    }

    private void saveCustomContacts(List<ContactItem> list) {
        try {
            JSONArray array = new JSONArray();
            for (ContactItem item : list) {
                JSONObject obj = new JSONObject();
                obj.put("id", item.getId());
                obj.put("name", item.getName());
                obj.put("phone", item.getPhoneOrHandle());
                obj.put("lastCalled", item.getLastCalledEpochMs());
                array.put(obj);
            }
            prefs.edit().putString(KEY_CUSTOM_CONTACTS, array.toString()).apply();
        } catch (Exception ignored) {
        }
    }

    private List<ContactItem> querySystemContacts() {
        List<ContactItem> results = new ArrayList<>();
        ContentResolver resolver = context.getContentResolver();
        String[] projection = new String[]{
                ContactsContract.CommonDataKinds.Phone._ID,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                ContactsContract.CommonDataKinds.Phone.NUMBER
        };
        try (Cursor cursor = resolver.query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                projection,
                null,
                null,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " ASC")) {
            if (cursor != null) {
                int idIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone._ID);
                int nameIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME);
                int numIdx = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER);
                while (cursor.moveToNext() && results.size() < 300) {
                    String id = idIdx >= 0 ? cursor.getString(idIdx) : "";
                    String name = nameIdx >= 0 ? cursor.getString(nameIdx) : "";
                    String number = numIdx >= 0 ? cursor.getString(numIdx) : "";
                    if (number != null && !number.trim().isEmpty()) {
                        results.add(new ContactItem(id, name, number, true, 0L));
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return results;
    }
}
