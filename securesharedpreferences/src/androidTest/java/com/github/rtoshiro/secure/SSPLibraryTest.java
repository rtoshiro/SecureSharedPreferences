package com.github.rtoshiro.secure;

import android.app.Application;
import android.content.Context;
import android.test.AndroidTestCase;
import android.test.mock.MockContext;

/**
 * <a href="http://d.android.com/tools/testing/testing_android.html">Testing Fundamentals</a>
 */
public class SSPLibraryTest extends AndroidTestCase {

    private final static String NAME = "secureTest";

    private final static String KEY_PUTSTRING = "stringkey";

    private final static String KEY_PUTINT_MAX = "maxintkey";
    private final static String KEY_PUTINT_MIN = "minintkey";

    private final static String KEY_PUTLONG_MAX = "maxlonbkey";
    private final static String KEY_PUTLONG_MIN = "minlongkey";

    private final static String KEY_PUTFLOAT_MAX = "maxfloatkey";
    private final static String KEY_PUTFLOAT_MIN = "minfloatkey";

    private final static String KEY_PUTBOOLEAN = "boolkey";

    private final static String toEncript = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sin tantum modo ad indicia veteris memoriae cognoscenda, curiosorum.";

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

    public void testEncript() {
        SecureSharedPreferences.Editor editor = secureSharedPreferences.edit();
        editor.setAutoCommit(false);

        assertEquals(secureSharedPreferences.getString(KEY_PUTSTRING, "No"), "No");
        assertEquals(secureSharedPreferences.getInt(KEY_PUTINT_MAX, Integer.MAX_VALUE), Integer.MAX_VALUE);
        assertEquals(secureSharedPreferences.getLong(KEY_PUTLONG_MAX, Long.MAX_VALUE), Long.MAX_VALUE);
        assertEquals(secureSharedPreferences.getFloat(KEY_PUTFLOAT_MAX, Float.MAX_VALUE), Float.MAX_VALUE);
        assertEquals(secureSharedPreferences.getBoolean(KEY_PUTBOOLEAN, true), true);


        assertTrue(editor.putString(KEY_PUTSTRING, toEncript).commit());

        assertTrue(editor.putInt(KEY_PUTINT_MAX, Integer.MAX_VALUE).commit());
        assertTrue(editor.putInt(KEY_PUTINT_MIN, Integer.MIN_VALUE).commit());

        assertTrue(editor.putLong(KEY_PUTLONG_MAX, Long.MAX_VALUE).commit());
        assertTrue(editor.putLong(KEY_PUTLONG_MIN, Long.MIN_VALUE).commit());

        assertTrue(editor.putFloat(KEY_PUTFLOAT_MAX, Float.MAX_VALUE).commit());
        assertTrue(editor.putFloat(KEY_PUTFLOAT_MIN, Float.MIN_VALUE).commit());

        assertTrue(editor.putBoolean(KEY_PUTBOOLEAN, false).commit());


        assertEquals(secureSharedPreferences.getString(KEY_PUTSTRING, "No"), toEncript);

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
}