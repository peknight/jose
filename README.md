# jose

我想搞个Scala函数式的ACME客户端来定期刷新获取新的证书用于创建支持https的服务。  

我也想搞个Scala函数式的OAuth2库。  

这两个都需要jose来支持，但是没太找到合适的Scala函数式的jose库。

倒是有一个jwt-circe库和一个scalajwk库，

但它们只实现了jose的部分功能，且不共享结构，甚至有些字段名都不符合jose规范。  

java倒是有一些功能齐全的jose库如jose4j，但是它不是函数式的我浑身难受。  

所以自己动手照着jose规范RFC8555和jose4j库手撸了一套基于cats-effect的函数式jose库。  

基本实现了RFC8555规范内的所有功能。  

测试用例也都是照着jose4j的单测完全写了一遍，基本测试都通过了。

什么？java加密的api也不太函数式且基本没啥类型安全保护？没事的，我也手撸了一套加密相关的函数式库security。