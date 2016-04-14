# SecureSharedPreferences

![build status](https://travis-ci.org/rtoshiro/SecureSharedPreferences.svg?branch=develop)

Because sometimes we would like to encrypt SharedPreferences' data.

### Usage

From SharedPreferences documented example:

```java
public class Calc extends Activity {
    public static final String PREFS_NAME = "MyPrefsFile";
    
    @Override
    protected void onCreate(Bundle state){
       super.onCreate(state);
       . . .

       // Restore preferences
       SecureSharedPreferences settings = new SecureSharedPreferences(this);
       boolean silent = settings.getBoolean("silentMode", false);
       setSilent(silent);
    }

    @Override
    protected void onStop(){
       super.onStop();

      // We need an Editor object to make preference changes.
      // All objects are from android.context.Context
      SecureSharedPreferences settings = new SecureSharedPreferences(this);
      SecureSharedPreferences.Editor editor = settings.edit();
      editor.putBoolean("silentMode", mSilentMode);

      // Commit the edits!
      // editor.commit(); // Autocommit is on by default ;)
    }
}
```

### API

All SharedPreferences methods were implemented except for SharedPreferences.getAll(). I'm still working on it.

And new constructors:

```java
    public SecureSharedPreferences(Context context);
    public SecureSharedPreferences(Context context, String key);
    public SecureSharedPreferences(Context context, String key, String secureName);
```

And now, supports:

```java
putSerializable(String key, Serializable object)
getSerializable(String key)
```
    
**You can save an Object (implements Serializable) and retrieve it later.
As it uses an bytearray version of the Serialized object, you have to pay attention when you update the object's Class because getSerializable method can return 'null' if you change some Class field.**

    
### Gradle

```
compile 'com.github.rtoshiro.securesharedpreferences:securesharedpreferences:1.1.0'
```

```
    repositories {
        mavenCentral()
    }
```

### Encryption

For encryption process, it uses [Facebook Conceal](https://facebook.github.io/conceal/)

It's very simple and functional.
