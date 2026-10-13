package top.hookvip.wxtablet.data

abstract class DescriptorData(
    private val key: String,
) {
    val mKey by lazy { "${HostInfo.toVerStr()}.$key" }
}