package com.github.rtoshiro.secure;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.facebook.android.crypto.keychain.SharedPrefsBackedKeyChain;
import com.facebook.crypto.Crypto;
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
 * Like SharedPreferences, but with encryption funcionality.
 *
 * @author rtoshiro
 * @version 2015.0529
 */
public class SecureSharedPreferences {

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
        public SharedPreferences.Editor putString(String keyValue, String value) {
            if (keyValue == null)
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
                    editor.putString(keyValue, cryptedBase64);
                    if (autoCommit) editor.commit();
                }
            } else
                editor.remove(keyValue);

            return this;
        }

        @Override
        @TargetApi(11)
        public SharedPreferences.Editor putStringSet(String keyValue, Set<String> values) {
            if (keyValue == null)
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

                    editor.putStringSet(keyValue, newSet);
                    if (autoCommit) editor.commit();

                } catch (KeyChainException | CryptoInitializationException | InstantiationException | IllegalAccessException | IOException e) {
                    e.printStackTrace();
                }

                return this;
            } else {
                editor.remove(keyValue);
                return this;
            }
        }

        @Override
        public SharedPreferences.Editor putInt(String keyValue, int value) {
            byte[] bytes = intToByteArray(value);
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = getCrypto().encrypt(bytes, getEntity());
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                editor.putString(keyValue, cryptedBase64);
                if (autoCommit) editor.commit();

                return this;
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String keyValue, long value) {
            byte[] bytes = long2ByteArray(value);
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = getCrypto().encrypt(bytes, getEntity());
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                editor.putString(keyValue, cryptedBase64);
                if (autoCommit) editor.commit();

                return this;
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String keyValue, float value) {
            byte[] bytes = float2ByteArray(value);
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = getCrypto().encrypt(bytes, getEntity());
            } catch (KeyChainException | CryptoInitializationException | IOException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                editor.putString(keyValue, cryptedBase64);
                if (autoCommit) editor.commit();

                return this;
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String keyValue, boolean value) {
            byte[] bytes = new byte[]{(byte) (value ? 1 : 0)};
            byte[] cryptedBytes = null;
            try {
                cryptedBytes = getCrypto().encrypt(bytes, getEntity());
            } catch (KeyChainException | IOException | CryptoInitializationException e) {
                e.printStackTrace();
            }

            if (cryptedBytes != null) {
                String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                editor.putString(keyValue, cryptedBase64);
                if (autoCommit) editor.commit();

                return this;
            }

            return this;
        }

        public SharedPreferences.Editor putSerializable(String keyValue, Serializable value) {
            byte[] bytes = serializable2ByteArray(value);
            if (bytes.length > 0) {
                byte[] cryptedBytes = null;
                try {
                    cryptedBytes = getCrypto().encrypt(bytes, getEntity());
                } catch (KeyChainException | CryptoInitializationException | IOException e) {
                    e.printStackTrace();
                }

                if (cryptedBytes.length > 0) {
                    String cryptedBase64 = Base64.encodeToString(cryptedBytes, Base64.NO_WRAP);

                    editor.putString(keyValue, cryptedBase64);
                    if (autoCommit) editor.commit();

                    return this;
                }
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            editor.remove(key);
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
     * Crypto and Entity objects - https://github.com/facebook/conceal
     */
    protected Crypto crypto;
    protected Entity entity;

    /**
     * SharedPreferences reference
     */
    protected SharedPreferences sharedPreferences;

    /**
     * Desired preferences file
     */
    protected String secureName = "SecureSharedPreferences";

    /**
     * AES encryption key
     */
    protected String key = "!S#,>D4kdke$2098f.?Dd2.,4@#$#%$e";

    /**
     * Constructor
     *
     * @param context The Context the object is running which it can access the getSharedPreferences and use it for encription process
     */
    public SecureSharedPreferences(Context context) {
        super();
        this.entity = new Entity(this.key);
        this.crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());
        this.sharedPreferences = context.getSharedPreferences(this.secureName, Context.MODE_PRIVATE);
    }

    /**
     * Constructor
     *
     * @param context The Context the object is running which it can access the getSharedPreferences and use it for encription process
     * @param key     Encription password
     */
    public SecureSharedPreferences(Context context, String key) {
        super();
        this.key = key;
        this.entity = new Entity(key);
        this.crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());
        this.sharedPreferences = context.getSharedPreferences(this.secureName, Context.MODE_PRIVATE);
    }

    /**
     * Constructor
     *
     * @param context    The Context the object is running which it can access the getSharedPreferences and use it for encription process
     * @param key        Encription password
     * @param secureName SharedPreferences preference file name
     */
    public SecureSharedPreferences(Context context, String key, String secureName) {
        super();
        if (secureName != null)
            this.secureName = secureName;

        this.key = key;
        this.entity = new Entity(key);
        this.crypto = new Crypto(new SharedPrefsBackedKeyChain(context), new SystemNativeCryptoLibrary());
        this.sharedPreferences = context.getSharedPreferences(secureName, Context.MODE_PRIVATE);
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
    public String getString(String keyValue, String defValue) {
        String result = defValue;
        String cryptedBase64 = sharedPreferences.getString(keyValue, null);
        if (cryptedBase64 != null) {
            byte[] cryptedBytes = Base64.decode(cryptedBase64, Base64.NO_WRAP);
            if (cryptedBytes != null) {
                byte[] plainBytes = null;
                try {
                    plainBytes = crypto.decrypt(cryptedBytes, entity);

                } catch (KeyChainException | CryptoInitializationException | IOException e) {
                    e.printStackTrace();
                }

                if (plainBytes != null)
                    result = new String(plainBytes);
            }
        }

        return result;
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public int getInt(String keyValue, int defValue) {
        int result = defValue;
        String cryptedBase64 = this.sharedPreferences.getString(keyValue, null);
        if (cryptedBase64 != null) {
            byte[] cryptedBytes = Base64.decode(cryptedBase64, Base64.NO_WRAP);
            if (cryptedBytes != null) {
                byte[] plainBytes = null;
                try {
                    plainBytes = crypto.decrypt(cryptedBytes, entity);

                } catch (KeyChainException | IOException | CryptoInitializationException e) {
                    e.printStackTrace();
                }

                if (plainBytes != null)
                    result = byteArrayToInt(plainBytes);
            }
        }
        return result;
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public float getFloat(String keyValue, float defValue) {
        float result = defValue;
        String cryptedBase64 = this.sharedPreferences.getString(keyValue, null);
        if (cryptedBase64 != null) {
            byte[] cryptedBytes = Base64.decode(cryptedBase64, Base64.NO_WRAP);
            if (cryptedBytes != null) {
                byte[] plainBytes = null;
                try {
                    plainBytes = crypto.decrypt(cryptedBytes, entity);

                } catch (KeyChainException | IOException | CryptoInitializationException e) {
                    e.printStackTrace();
                }

                if (plainBytes != null)
                    result = byteArrayToFloat(plainBytes);
            }
        }
        return result;
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public long getLong(String keyValue, long defValue) {
        long result = defValue;
        String cryptedBase64 = this.sharedPreferences.getString(keyValue, null);
        if (cryptedBase64 != null) {
            byte[] cryptedBytes = Base64.decode(cryptedBase64, Base64.NO_WRAP);
            if (cryptedBytes != null) {
                byte[] plainBytes = null;
                try {
                    plainBytes = crypto.decrypt(cryptedBytes, entity);

                } catch (KeyChainException | IOException | CryptoInitializationException e) {
                    e.printStackTrace();
                }

                if (plainBytes != null)
                    result = byteArrayToLong(plainBytes);
            }
        }
        return result;
    }

    /**
     * Like {@link SharedPreferences}
     * http://developer.android.com/reference/android/content/SharedPreferences.html
     */
    public boolean getBoolean(String keyValue, boolean defValue) {
        boolean result = defValue;
        String cryptedBase64 = this.sharedPreferences.getString(keyValue, null);
        if (cryptedBase64 != null) {
            byte[] cryptedBytes = Base64.decode(cryptedBase64, Base64.NO_WRAP);
            if (cryptedBytes != null) {
                byte[] plainBytes = null;
                try {
                    plainBytes = crypto.decrypt(cryptedBytes, entity);

                } catch (KeyChainException | IOException | CryptoInitializationException e) {
                    e.printStackTrace();
                }

                if (plainBytes != null)
                    result = plainBytes[0] != 0;
            }
        }
        return result;
    }

    /**
     * Get an Serializable object
     *
     * @param keyValue Key name
     * @return The object
     */
    public Object getSerializable(String keyValue) {
        Object result = null;
        String cryptedBase64 = this.sharedPreferences.getString(keyValue, null);
        if (cryptedBase64 != null) {
            byte[] cryptedBytes = Base64.decode(cryptedBase64, Base64.NO_WRAP);
            if (cryptedBytes.length > 0) {
                byte[] plainBytes = null;
                try {
                    plainBytes = crypto.decrypt(cryptedBytes, entity);

                } catch (KeyChainException | IOException | CryptoInitializationException e) {
                    e.printStackTrace();
                }

                if (plainBytes.length > 0) {
                    result = byteArrayToSerializable(plainBytes);
                }
            }
        }
        return result;
    }

    public boolean contains(String key) {
        return this.sharedPreferences.contains(key);
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

    protected static byte[] long2ByteArray(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    protected static long byteArrayToLong(byte[] b) {
        ByteBuffer buf = ByteBuffer.wrap(b);
        return buf.getLong();
    }

    protected static byte[] float2ByteArray(float value) {
        return ByteBuffer.allocate(4).putFloat(value).array();
    }

    protected static float byteArrayToFloat(byte[] b) {
        ByteBuffer buf = ByteBuffer.wrap(b);
        return buf.getFloat();
    }

    protected static byte[] serializable2ByteArray(Serializable object) {
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
