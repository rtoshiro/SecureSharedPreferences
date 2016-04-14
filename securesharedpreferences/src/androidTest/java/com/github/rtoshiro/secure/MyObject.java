package com.github.rtoshiro.secure;

import java.io.Serializable;

/**
 * Created by Tox on 4/14/16.
 */
public class MyObject implements Serializable {
    private String name;
    private int age;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }
}