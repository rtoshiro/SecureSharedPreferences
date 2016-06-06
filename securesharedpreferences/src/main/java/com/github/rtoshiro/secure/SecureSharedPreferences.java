package com.github.rtoshiro.secure;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Base64;

import com.facebook.android.crypto.keychain.AndroidConceal;
import com.facebook.android.crypto.keychain.SharedPrefsBackedKeyChain;
import com.facebook.crypto.Crypto;
import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.Entity;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.ParameterizedType;
import java.nio.ByteBuffer;
import java.util.Set;

/**
 * Like SharedPreferences, but with encryption functionality.
 *
 * @author rtoshiro
 * @version 2015.0529
 */
public class SecureSharedPreferences {
    protected static final String HIGH_BIT_ENCRYPTION_KEY = "_HBE";

    public class Editor implements SharedPreferences.Editor {
        /**
         * Means commit() is called automatically after each putSomething()
         */
        private boolean autoCommit = true;

        /**
         * Current SharedPreferences.Editor object
         */
        protected SharedPreferences.Editor editor;

        protected Editor() {
            this.editor = getSharedPreferences().edit();
        }

        protected Editor(boolean autoCommit) {
            this.editor = getSharedPreferences().edit();
            this.autoCommit = autoCommit;
        }

        /**
         * Tells it if it has to commit after each change
         *
         * @return
         */
        public boolean isAutoCommit() {
            return autoCommit;
        }

        public void setAutoCommit(boolean autoCommit) {
            this.autoCommit = autoCommit;
        }

        @Override
        public SharedPreferences.Editor putString(String key, String value) {
            if (key == null)
                return this;

            if (value != null) {
                byte[] cryptedBytes = null;
                try {
                    cryptedBytes = getCrypto().encrypt(value.getBytes(), getEntity());
                } catch (KeyChainException | CryptoInitializationException | IOException e) {
                    e.printStackTrace();
                }

                if (cryptedBytes != null) {
                    String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);
                    editor.putString(key + HIGH_BIT_ENCRYPTION_KEY, cryptedBase64);
                    if (autoCommit) editor.commit();
                }
            } else {
                editor.remove(key + HIGH_BIT_ENCRYPTION_KEY);
            }

            return this;
        }

        @Override
        @TargetApi(Build.VERSION_CODES.HONEYCOMB)
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) {
            if (key == null)
                return this;

            if (values != null) {
                Set<String> newSet;
                byte[] cryptedBytes;
                try {
                    newSet = (Set) ((Class) ((ParameterizedType) values.getClass().getGenericSuperclass()).getActualTypeArguments()[0]).newInstance();

                    // Creates a new Set<String>
                    for (String value : values) {
                        cryptedBytes = getCrypto().encrypt(value.getBytes(), getEntity());
                        if (cryptedBytes != null) {
                            String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);
                            newSet.add(cryptedBase64);
                        }
                    }

                    editor.putStringSet(key + HIGH_BIT_ENCRYPTION_KEY, newSet);
                    if (autoCommit) editor.commit();
                } catch (KeyChainException | CryptoInitializationException | InstantiationException | IllegalAccessException | IOException e) {
                    e.printStackTrace();
                }

                return this;
            } else {
                editor.remove(key + HIGH_BIT_ENCRYPTION_KEY);
                return this;
            }
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            byte[] bytes = intToByteArray(value);
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = getCrypto().encrypt(bytes, getEntity());
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                editor.putString(key + HIGH_BIT_ENCRYPTION_KEY, cryptedBase64);
                if (autoCommit) editor.commit();

                return this;
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            byte[] bytes = longToByteArray(value);
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = getCrypto().encrypt(bytes, getEntity());
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                editor.putString(key + HIGH_BIT_ENCRYPTION_KEY, cryptedBase64);
                if (autoCommit) editor.commit();

                return this;
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            byte[] bytes = floatToByteArray(value);
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = getCrypto().encrypt(bytes, getEntity());
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                editor.putString(key + HIGH_BIT_ENCRYPTION_KEY, cryptedBase64);
                if (autoCommit) editor.commit();

                return this;
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            byte[] bytes = new byte[]{(byte) (value ? 1 : 0)};
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = getCrypto().encrypt(bytes, getEntity());
            } catch (KeyChainException | IOException | CryptoInitializationException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                editor.putString(key + HIGH_BIT_ENCRYPTION_KEY, cryptedBase64);
                if (autoCommit) editor.commit();

                return this;
            }

            return this;
        }

        public SharedPreferences.Editor putSerializable(String key, Serializable value) {
            byte[] bytes = serializableToByteArray(value);
            if (bytes.length > 0) {
                byte[] cryptedBytes = null;
                try {
                    cryptedBytes = getCrypto().encrypt(bytes, getEntity());
                } catch (KeyChainException | CryptoInitializationException | IOException e) {
                    e.printStackTrace();
                }

                if (cryptedBytes.length > 0) {
                    String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                    editor.putString(key + HIGH_BIT_ENCRYPTION_KEY, cryptedBase64);
                    if (autoCommit) editor.commit();

                    return this;
                }
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            editor.remove(key);
            editor.remove(key + HIGH_BIT_ENCRYPTION_KEY);
            if (autoCommit) editor.commit();

            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            editor.clear();
            editor.commit();
            return this;
        }

        @Override
        public boolean commit() {
            return editor.commit();
        }

        @Override
        public void apply() {
            editor.apply();
        }
    }

    public interface OnSharedPreferenceChangeListener extends SharedPreferences.OnSharedPreferenceChangeListener {

    }

    /**
     * Legacy Crypto and Entity objects for older versions of Conceal - https://github.com/facebook/conceal
     */
    private Crypto legacyCrypto;
    private Entity legacyEntity;

    /**
     * Crypto and Entity objects for newer versions of Conceal - https://github.com/facebook/conceal
     */
    private Crypto crypto;
    private Entity entity;

    /**
     * SharedPreferences reference
     */
    private SharedPreferences sharedPreferences;

    /**
     * Desired preferences file
     */
    private String securePrefsName = "SecureSharedPreferences";

    /**
     * AES encryption secureKey
     */
    private String encryptionKey = "!S#,>D4kdke$2098f.?Dd2.,4@#$#%$e";

    /**
     * Constructor
     *
     * @param context The Context the object is running which it can access the getSharedPreferences and use it for Encryption process
     */
    public SecureSharedPreferences(Context context) {
        super();

        this.legacyEntity = new Entity(this.encryptionKey);
        this.legacyCrypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

        this.entity = Entity.create(encryptionKey);
        this.crypto = AndroidConceal.get().createDefaultCrypto(new SharedPrefsBackedKeyChain(context, CryptoConfig.KEY_256));

        this.sharedPreferences = context.getSharedPreferences(this.securePrefsName, Context.MODE_PRIVATE);
    }

    /**
     * Constructor
     *
     * @param context   The Context the object is running which it can access the getSharedPreferences and use it for Encryption process
     * @param encryptionKey Encryption password
     */
    public SecureSharedPreferences(Context context, String encryptionKey) {
        super();

        this.encryptionKey = encryptionKey;

        this.legacyEntity = new Entity(encryptionKey);
        this.legacyCrypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

        this.entity = Entity.create(encryptionKey);
        this.crypto = AndroidConceal.get().createDefaultCrypto(new SharedPrefsBackedKeyChain(context, CryptoConfig.KEY_256));

        this.sharedPreferences = context.getSharedPreferences(this.securePrefsName, Context.MODE_PRIVATE);
    }

    /**
     * Constructor
     *
     * @param context         The Context the object is running which it can access the getSharedPreferences and use it for Encryption process
     * @param encryptionKey       Encryption password
     * @param securePrefsName SharedPreferences preference file name
     */
    public SecureSharedPreferences(Context context, String encryptionKey, String securePrefsName) {
        super();

        if (securePrefsName != null) {
            this.securePrefsName = securePrefsName;
        }

        this.encryptionKey = encryptionKey;

        this.legacyEntity = new Entity(encryptionKey);
        this.legacyCrypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());

        this.entity = Entity.create(encryptionKey);
        this.crypto = AndroidConceal.get().createDefaultCrypto(new SharedPrefsBackedKeyChain(context, CryptoConfig.KEY_256));

        this.sharedPreferences = context.getSharedPreferences(securePrefsName, Context.MODE_PRIVATE);
    }

    public SecureSharedPreferences.Editor edit() {
        return new SecureSharedPreferences.Editor();
    }

    /**
     * Create a new instance of SecureSharedPreferences.Editor with autoCommit
     *
     * @param autoCommit true (default) to call commit() after each put method
     * @return The new instance of SecureSharedPreferences.Editor
     */
    public SecureSharedPreferences.Editor edit(boolean autoCommit) {
        return new SecureSharedPreferences.Editor(autoCommit);
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public String getString(String key, String defaultValue) {
        // Check higher bit encrypted value first
        String possibleDecryptedValue = getDecryptedValue(String.class, key, true);

        if (possibleDecryptedValue == null) {
            // No high-bit encrypted value, so now check for a lower-bit encrypted value
            possibleDecryptedValue = getDecryptedValue(String.class, key, false);

            if (possibleDecryptedValue != null) {
                transitionString(key, possibleDecryptedValue);
            }
        }

        return possibleDecryptedValue != null ? possibleDecryptedValue : defaultValue;
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public int getInt(String key, int defaultValue) {
        // Check higher bit encrypted value first
        Integer possibleDecryptedValue = getDecryptedValue(Integer.class, key, true);

        if (possibleDecryptedValue == null) {
            // No high-bit encrypted value, so now check for a lower-bit encrypted value
            possibleDecryptedValue = getDecryptedValue(Integer.class, key, false);

            if (possibleDecryptedValue != null) {
                transitionInt(key, possibleDecryptedValue);
            }
        }

        return possibleDecryptedValue != null ? possibleDecryptedValue : defaultValue;
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public float getFloat(String key, float defaultValue) {
        // Check higher bit encrypted value first
        Float possibleDecryptedValue = getDecryptedValue(Float.class, key, true);

        if (possibleDecryptedValue == null) {
            // No high-bit encrypted value, so now check for a lower-bit encrypted value
            possibleDecryptedValue = getDecryptedValue(Float.class, key, false);

            if (possibleDecryptedValue != null) {
                transitionFloat(key, possibleDecryptedValue);
            }
        }

        return possibleDecryptedValue != null ? possibleDecryptedValue : defaultValue;
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public long getLong(String key, long defaultValue) {
        // Check higher bit encrypted value first
        Long possibleDecryptedValue = getDecryptedValue(Long.class, key, true);

        if (possibleDecryptedValue == null) {
            // No high-bit encrypted value, so now check for a lower-bit encrypted value
            possibleDecryptedValue = getDecryptedValue(Long.class, key, false);

            if (possibleDecryptedValue != null) {
                transitionLong(key, possibleDecryptedValue);
            }
        }

        return possibleDecryptedValue != null ? possibleDecryptedValue : defaultValue;
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public boolean getBoolean(String key, boolean defaultValue) {
        // Check higher bit encrypted value first
        Boolean possibleDecryptedValue = getDecryptedValue(Boolean.class, key, true);

        if (possibleDecryptedValue == null) {
            // No high-bit encrypted value, so now check for a lower-bit encrypted value
            possibleDecryptedValue = getDecryptedValue(Boolean.class, key, false);

            if (possibleDecryptedValue != null) {
                transitionBoolean(key, possibleDecryptedValue);
            }
        }

        return possibleDecryptedValue != null ? possibleDecryptedValue : defaultValue;
    }

    /**
     * Get an Serializable object
     *
     * @param key Key name
     * @return The object
     */
    public Object getSerializable(String key) {
        // Check higher bit encrypted value first
        Serializable possibleDecryptedValue = getDecryptedValue(key, true);

        if (possibleDecryptedValue == null) {
            // No high-bit encrypted value, so now check for a lower-bit encrypted value
            possibleDecryptedValue = getDecryptedValue(key, false);

            if (possibleDecryptedValue != null) {
                transitionSerializable(key, possibleDecryptedValue);
            }
        }

        return possibleDecryptedValue;
    }

    private Serializable getDecryptedValue(String key, boolean highEncryption) {
        return getDecryptedValue(Serializable.class, key, highEncryption);
    }

    private <T extends Serializable> T getDecryptedValue(Class<T> type, String key, boolean highEncryption) {
        byte[] decryptedBytes = getDecryptedBytes(key, highEncryption);

        if (decryptedBytes != null) {
            if (type == Integer.class) {
                return type.cast(byteArrayToInt(decryptedBytes));
            } else if (type == Long.class) {
                return type.cast(byteArrayToLong(decryptedBytes));
            } else if (type == Float.class) {
                return type.cast(byteArrayToFloat(decryptedBytes));
            } else if (type == Boolean.class) {
                return type.cast(decryptedBytes[0] != 0);
            } else if (type == String.class) {
                return type.cast(new String(decryptedBytes));
            } else  {
                return type.cast(byteArrayToSerializable(decryptedBytes));
            }
        }

        return null;
    }

    private byte[] getDecryptedBytes(String key, boolean highEncryption) {
        byte[] decryptedBytes = null;

        String realKey = highEncryption ? key + HIGH_BIT_ENCRYPTION_KEY : key;
        String encryptedValue = sharedPreferences.getString(realKey, null);

        if (encryptedValue != null) {
            byte[] encryptedBytes;
            encryptedBytes = Base64.decode(encryptedValue, Base64.NO_WRAP);

            if (encryptedBytes != null) {
                try {
                    if (highEncryption) {
                        decryptedBytes = crypto.decrypt(encryptedBytes, entity);
                    } else {
                        decryptedBytes = legacyCrypto.decrypt(encryptedBytes, legacyEntity);
                    }
                } catch (KeyChainException | CryptoInitializationException | IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return decryptedBytes;
    }

    private void transitionString(String key, String value) {
        this.edit(true).putString(key, value);
        this.sharedPreferences.edit().remove(key).commit();
    }

    private void transitionInt(String key, int value) {
        this.edit(true).putInt(key, value);
        this.sharedPreferences.edit().remove(key).commit();
    }

    private void transitionFloat(String key, float value) {
        this.edit(true).putFloat(key, value);
        this.sharedPreferences.edit().remove(key).commit();
    }

    private void transitionLong(String key, long value) {
        this.edit(true).putLong(key, value);
        this.sharedPreferences.edit().remove(key).commit();
    }

    private void transitionBoolean(String key, boolean value) {
        this.edit(true).putBoolean(key, value);
        this.sharedPreferences.edit().remove(key).commit();
    }

    private void transitionSerializable(String key, Serializable value) {
        edit().putSerializable(key, value).commit();
        this.sharedPreferences.edit().remove(key).commit();
    }

    public boolean contains(String key) {
        return this.sharedPreferences.contains(key) || this.sharedPreferences.contains(key + HIGH_BIT_ENCRYPTION_KEY);
    }

    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        this.sharedPreferences.registerOnSharedPreferenceChangeListener(listener);
    }

    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        this.sharedPreferences.unregisterOnSharedPreferenceChangeListener(listener);
    }

    protected static byte[] intToByteArray(int a) {
        byte[] ret = new byte[4];
        ret[3] = (byte) (a & 0xFF);
        ret[2] = (byte) ((a >> 8) & 0xFF);
        ret[1] = (byte) ((a >> 16) & 0xFF);
        ret[0] = (byte) ((a >> 24) & 0xFF);
        return ret;
    }

    protected static int byteArrayToInt(byte[] b) {
        return (b[3] & 0xFF) + ((b[2] & 0xFF) << 8) + ((b[1] & 0xFF) << 16) + ((b[0] & 0xFF) << 24);
    }

    protected static byte[] longToByteArray(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    protected static long byteArrayToLong(byte[] b) {
        ByteBuffer buf = ByteBuffer.wrap(b);
        return buf.getLong();
    }

    protected static byte[] floatToByteArray(float value) {
        return ByteBuffer.allocate(4).putFloat(value).array();
    }

    protected static float byteArrayToFloat(byte[] b) {
        ByteBuffer buf = ByteBuffer.wrap(b);
        return buf.getFloat();
    }

    protected static byte[] serializableToByteArray(Serializable object) {
        byte[] result = new byte[0];
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(object);
            result = bos.toByteArray();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ex) {
                // ignore close exception
            }
            try {
                bos.close();
            } catch (IOException ex) {
                // ignore close exception
            }
        }

        return result;
    }

    protected static Serializable byteArrayToSerializable(byte[] bytes) {
        Serializable o = null;
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInput in = null;
        try {
            in = new ObjectInputStream(bis);
            o = (Serializable) in.readObject();
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
        } finally {
            try {
                bis.close();
            } catch (IOException ex) {
                // ignore close exception
            }
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException ex) {
                // ignore close exception
            }
        }
        return o;
    }

    private Crypto getCrypto() {
        return crypto;
    }

    private Entity getEntity() {
        return entity;
    }

    private SharedPreferences getSharedPreferences() {
        return sharedPreferences;
    }
}
