package cn.labzen.algorithm.meta;

import cn.labzen.meta.component.DeclaredComponent;

public class AlgorithmMeta implements DeclaredComponent {

  @Override
  public String mark() {
    return "Labzen.Algorithm";
  }

  @Override
  public String packageBased() {
    return "cn.labzen.algorithm";
  }

  @Override
  public String description() {
    return "算法包，提供常用的算法功能封装，例如（非）对称、散列算法等，加速开发";
  }
}
