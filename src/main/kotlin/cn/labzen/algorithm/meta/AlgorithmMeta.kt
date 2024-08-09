package cn.labzen.algorithm.meta

import cn.labzen.meta.component.LabzenComponent

class AlgorithmMeta : LabzenComponent {

  override fun mark(): String =
    "Labzen.Algorithm"

  override fun packageBased(): String =
    "cn.labzen.algorithm"

  override fun description(): String =
    "算法包，提供常用的算法功能封装，例如（非）对称、散列算法等，加速开发"
}
