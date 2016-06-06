package com.github.rtoshiro.secure;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.test.AndroidTestCase;
import android.util.Base64;

import com.facebook.android.crypto.keychain.SharedPrefsBackedKeyChain;
import com.facebook.crypto.Crypto;
import com.facebook.crypto.Entity;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.ParameterizedType;
import java.util.Set;

import static com.github.rtoshiro.secure.SecureSharedPreferences.floatToByteArray;
import static com.github.rtoshiro.secure.SecureSharedPreferences.intToByteArray;
import static com.github.rtoshiro.secure.SecureSharedPreferences.longToByteArray;
import static com.github.rtoshiro.secure.SecureSharedPreferences.serializableToByteArray;

/**
 * <a href="http://d.android.com/tools/testing/testing_android.html">Testing Fundamentals</a>
 */
public class SSPLibraryTest extends AndroidTestCase {
    private final static String SECURE_NAME = "SecureSharedPreferences";
    private final static String NAME = "secureTest";

    private final static String KEY_PUTSTRING = "stringkey";

    private final static String KEY_PUTINT_MAX = "maxintkey";
    private final static String KEY_PUTINT_MIN = "minintkey";

    private final static String KEY_PUTLONG_MAX = "maxlonbkey";
    private final static String KEY_PUTLONG_MIN = "minlongkey";

    private final static String KEY_PUTFLOAT_MAX = "maxfloatkey";
    private final static String KEY_PUTFLOAT_MIN = "minfloatkey";

    private final static String KEY_PUTBOOLEAN = "boolkey";

    private final static String KEY_PUTOBJECT = "serialkey";

    private final static String toEncrypt = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sin tantum modo ad indicia veteris memoriae cognoscenda, curiosorum.";

    private Context context;
    private SecureSharedPreferences secureSharedPreferences;

    public SSPLibraryTest() {
        super();
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        context = getContext();
        assertNotNull(context);

        secureSharedPreferences = new SecureSharedPreferences(context, NAME);

        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.clear();
    }

    public void testEncrypt() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        assertEquals(secureSharedPreferences.getString(KEY_PUTSTRING, "No"), "No");
        assertEquals(secureSharedPreferences.getInt(KEY_PUTINT_MAX, Integer.MAX_VALUE), Integer.MAX_VALUE);
        assertEquals(secureSharedPreferences.getLong(KEY_PUTLONG_MAX, Long.MAX_VALUE), Long.MAX_VALUE);
        assertEquals(secureSharedPreferences.getFloat(KEY_PUTFLOAT_MAX, Float.MAX_VALUE), Float.MAX_VALUE);
        assertEquals(secureSharedPreferences.getBoolean(KEY_PUTBOOLEAN, true), true);


        assertTrue(editor.putString(KEY_PUTSTRING, toEncrypt).commit());

        assertTrue(editor.putInt(KEY_PUTINT_MAX, Integer.MAX_VALUE).commit());
        assertTrue(editor.putInt(KEY_PUTINT_MIN, Integer.MIN_VALUE).commit());

        assertTrue(editor.putLong(KEY_PUTLONG_MAX, Long.MAX_VALUE).commit());
        assertTrue(editor.putLong(KEY_PUTLONG_MIN, Long.MIN_VALUE).commit());

        assertTrue(editor.putFloat(KEY_PUTFLOAT_MAX, Float.MAX_VALUE).commit());
        assertTrue(editor.putFloat(KEY_PUTFLOAT_MIN, Float.MIN_VALUE).commit());

        assertTrue(editor.putBoolean(KEY_PUTBOOLEAN, false).commit());


        assertEquals(secureSharedPreferences.getString(KEY_PUTSTRING, "No"), toEncrypt);

        assertEquals(secureSharedPreferences.getInt(KEY_PUTINT_MAX, Integer.MIN_VALUE), Integer.MAX_VALUE);
        assertEquals(secureSharedPreferences.getInt(KEY_PUTINT_MIN, Integer.MAX_VALUE), Integer.MIN_VALUE);

        assertEquals(secureSharedPreferences.getLong(KEY_PUTLONG_MAX, Long.MIN_VALUE), Long.MAX_VALUE);
        assertEquals(secureSharedPreferences.getLong(KEY_PUTLONG_MIN, Long.MAX_VALUE), Long.MIN_VALUE);

        assertEquals(secureSharedPreferences.getFloat(KEY_PUTFLOAT_MAX, Float.MIN_VALUE), Float.MAX_VALUE);
        assertEquals(secureSharedPreferences.getFloat(KEY_PUTFLOAT_MIN, Float.MAX_VALUE), Float.MIN_VALUE);

        assertEquals(secureSharedPreferences.getBoolean(KEY_PUTBOOLEAN, true), false);

        assertTrue(editor.putString(KEY_PUTSTRING, null).commit());
        assertNull(secureSharedPreferences.getString(KEY_PUTSTRING, null));

        assertTrue(editor.putInt(KEY_PUTINT_MAX, 90).commit());
        assertEquals(secureSharedPreferences.getInt(KEY_PUTINT_MAX, Integer.MIN_VALUE), 90);

        assertTrue(editor.putLong(KEY_PUTLONG_MAX, 90L).commit());
        assertEquals(secureSharedPreferences.getLong(KEY_PUTLONG_MAX, Long.MIN_VALUE), 90L);

        assertTrue(editor.putFloat(KEY_PUTFLOAT_MAX, 90.f).commit());
        assertEquals(secureSharedPreferences.getFloat(KEY_PUTFLOAT_MAX, Float.MIN_VALUE), 90.f);
    }

    public void testSerializable() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        MyObject myObject = new MyObject();
        myObject.setAge(10);
        myObject.setName("Name");

        assertTrue(editor.putSerializable(KEY_PUTOBJECT, myObject).commit());

        MyObject newObject = (MyObject) secureSharedPreferences.getSerializable(KEY_PUTOBJECT);
        assertNotNull(newObject);
        assertEquals(newObject.getAge(), myObject.getAge());
        assertEquals(newObject.getName(), myObject.getName());
    }

    public void testStringTransition() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        putLegacyString(KEY_PUTSTRING, toEncrypt);
        assertEquals(secureSharedPreferences.getString(KEY_PUTSTRING, "No"), toEncrypt);

        SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
        assertFalse("Legacy encrypted value should be gone, but it still present", rawPrefs.contains(KEY_PUTSTRING));
        assertTrue("Hit bit-level ncrypted value should be present, but is gone",
                rawPrefs.contains(KEY_PUTSTRING + SecureSharedPreferences.HIGH_BIT_ENCRYPTION_KEY));
    }

    public void testIntegerTransition() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        putLegacyInt(KEY_PUTINT_MAX, Integer.MAX_VALUE);
        assertEquals(secureSharedPreferences.getInt(KEY_PUTINT_MAX, Integer.MIN_VALUE), Integer.MAX_VALUE);

        SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
        assertFalse("Legacy encrypted value should be gone, but it still present", rawPrefs.contains(KEY_PUTINT_MAX));
        assertTrue("Hit bit-level ncrypted value should be present, but is gone",
                rawPrefs.contains(KEY_PUTINT_MAX + SecureSharedPreferences.HIGH_BIT_ENCRYPTION_KEY));
    }

    public void testLongTransition() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        putLegacyLong(KEY_PUTLONG_MAX, Long.MAX_VALUE);
        assertEquals(secureSharedPreferences.getLong(KEY_PUTLONG_MAX, Long.MIN_VALUE), Long.MAX_VALUE);

        SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
        assertFalse("Legacy encrypted value should be gone, but it still present", rawPrefs.contains(KEY_PUTLONG_MAX));
        assertTrue("Hit bit-level ncrypted value should be present, but is gone",
                rawPrefs.contains(KEY_PUTLONG_MAX + SecureSharedPreferences.HIGH_BIT_ENCRYPTION_KEY));
    }

    public void testFloatTransition() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        putLegacyFloat(KEY_PUTFLOAT_MAX, Float.MAX_VALUE);
        assertEquals(secureSharedPreferences.getFloat(KEY_PUTFLOAT_MAX, Float.MIN_VALUE), Float.MAX_VALUE);

        SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
        assertFalse("Legacy encrypted value should be gone, but it still present", rawPrefs.contains(KEY_PUTFLOAT_MAX));
        assertTrue("Hit bit-level ncrypted value should be present, but is gone",
                rawPrefs.contains(KEY_PUTFLOAT_MAX + SecureSharedPreferences.HIGH_BIT_ENCRYPTION_KEY));
    }

    public void testBooleanTransition() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        putLegacyBoolean(KEY_PUTBOOLEAN, true);
        assertTrue(secureSharedPreferences.getBoolean(KEY_PUTBOOLEAN, false));

        SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
        assertFalse("Legacy encrypted value should be gone, but it still present", rawPrefs.contains(KEY_PUTBOOLEAN));
        assertTrue("Hit bit-level ncrypted value should be present, but is gone",
                rawPrefs.contains(KEY_PUTBOOLEAN + SecureSharedPreferences.HIGH_BIT_ENCRYPTION_KEY));
    }

    public void testSerializableTransition() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        MyObject myObject = new MyObject();
        myObject.setAge(10);
        myObject.setName("Name");

        putLegacySerializable(KEY_PUTOBJECT, myObject);

        MyObject newObject = (MyObject) secureSharedPreferences.getSerializable(KEY_PUTOBJECT);

        assertNotNull(newObject);
        assertEquals(newObject.getAge(), myObject.getAge());
        assertEquals(newObject.getName(), myObject.getName());

        SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
        assertFalse("Legacy encrypted value should be gone, but it still present", rawPrefs.contains(KEY_PUTOBJECT));
        assertTrue("Hit bit-level ncrypted value should be present, but is gone",
                rawPrefs.contains(KEY_PUTOBJECT + SecureSharedPreferences.HIGH_BIT_ENCRYPTION_KEY));
    }

    private void putLegacyString(String key, String value) {
        if (key == null)
            return;

        if (value != null) {
            Entity entity = new Entity(NAME);
            Crypto crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

            byte[] cryptedBytes = null;
            try {
                cryptedBytes = crypto.encrypt(value.getBytes(), entity);
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                rawPrefs.edit().putString(key, cryptedBase64).commit();
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    private void putLegacyStringSet(String key, Set<String> values) {
        if (key == null)
            return;

        if (values != null) {
            Entity entity = new Entity(NAME);
            Crypto crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

            Set<String> newSet;
            byte[] cryptedBytes;
            try {
                newSet = (Set) ((Class) ((ParameterizedType) values.getClass().getGenericSuperclass()).getActualTypeArguments()[0]).newInstance();

                // Creates a new Set<String>
                for (String value : values) {
                    cryptedBytes = crypto.encrypt(value.getBytes(), entity);
                    if (cryptedBytes != null) {
                        String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);
                        newSet.add(cryptedBase64);
                    }
                }

                SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
                rawPrefs.edit().putStringSet(key, newSet).commit();

            } catch (KeyChainException | CryptoInitializationException | InstantiationException | IllegalAccessException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void putLegacyInt(String key, int value) {
        Entity entity = new Entity(NAME);
        Crypto crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

        byte[] bytes = intToByteArray(value);
        byte[] cryptedBytes = null;
        try {
            cryptedBytes = crypto.encrypt(bytes, entity);
        } catch (KeyChainException | CryptoInitializationException | IOException e) {
            e.printStackTrace();
        }

        if (cryptedBytes != null) {
            SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
            String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

            rawPrefs.edit().putString(key, cryptedBase64).commit();
        }
    }

    private void putLegacyLong(String key, long value) {
        Entity entity = new Entity(NAME);
        Crypto crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

        byte[] bytes = longToByteArray(value);
        byte[] cryptedBytes = null;
        try {
            cryptedBytes = crypto.encrypt(bytes, entity);
        } catch (KeyChainException | CryptoInitializationException | IOException e) {
            e.printStackTrace();
        }

        if (cryptedBytes != null) {
            SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
            String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

            rawPrefs.edit().putString(key, cryptedBase64).commit();
        }
    }

    private void putLegacyFloat(String key, float value) {
        Entity entity = new Entity(NAME);
        Crypto crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

        byte[] bytes = floatToByteArray(value);
        byte[] cryptedBytes = null;
        try {
            cryptedBytes = crypto.encrypt(bytes, entity);
        } catch (KeyChainException | CryptoInitializationException | IOException e) {
            e.printStackTrace();
        }

        if (cryptedBytes != null) {
            SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
            String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

            rawPrefs.edit().putString(key, cryptedBase64).commit();
        }
    }

    private void putLegacyBoolean(String key, boolean value) {
        Entity entity = new Entity(NAME);
        Crypto crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

        byte[] bytes = new byte[]{(byte) (value ? 1 : 0)};
        byte[] cryptedBytes = null;
        try {
            cryptedBytes = crypto.encrypt(bytes, entity);
        } catch (KeyChainException | IOException | CryptoInitializationException e) {
            e.printStackTrace();
        }

        if (cryptedBytes != null) {
            SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
            String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

            rawPrefs.edit().putString(key, cryptedBase64).commit();
        }
    }

    private void putLegacySerializable(String key, Serializable value) {
        Entity entity = new Entity(NAME);
        Crypto crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

        byte[] bytes = serializableToByteArray(value);
        if (bytes.length > 0) {
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = crypto.encrypt(bytes, entity);
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null && cryptedBytes.length > 0) {
                SharedPreferences rawPrefs = context.getSharedPreferences(SECURE_NAME, Context.MODE_PRIVATE);
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                rawPrefs.edit().putString(key, cryptedBase64).commit();
            }
        }
    }
}