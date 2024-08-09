package cn.labzen.algorithm.crypto;

import java.io.Serializable;

public class SimpleBean implements Serializable {

  private final String name;
  private final int age;

  public SimpleBean(String name, int age) {
    this.name = name;
    this.age = age;
  }

  public String getName() {
    return name;
  }

  public int getAge() {
    return age;
  }
}
