# frida-script
这里放着一些常用的frida hook脚本

## sslUnpinning.js

### 用法
```
frida -U -f [AppPackageName] --no-pause -l sslUnpinning.js
(-f spawn指定的App)
或
frida -U -F --no-pause -l sslUnpinning.js
(-F attach到当前在最前面的应用程序)
```

### 描述
用于绕过 SSL Pinning，作用和 JustTrustMe 一样  
在脚本基础上修改 [https://www.jianshu.com/p/f07ad151a163](https://www.jianshu.com/p/f07ad151a163)  
主要增加了对 `WebViewClient` 的 `onReceivedSslError` 方法的 hook  
以及尝试对继承了 WebViewClient 的子类的查找和 hook  

一般情况下，Hook了 `TrustManagerImpl` 、 `okhttp3.CertificatePinner` 和 `TrustManagers` 等中的证书校验相关的函数后，`WebView` 中的请求也不会出现证书错误的问题，但是，保不住不知道为啥偶尔还是会有 SSL错误异常  
所以，索性把 `WebViewClient` 的 `onReceivedSslError` 方法也 hook 了  
此函数在发生SSL错误时会被执行，此函数的第二个参数传入一个 `handler` 对象，我们只需要调用 `handler.proceed()` 忽略SSL错误即可  

另外，当App中大部分功能基于 `WebView` 开发时，App本身可能会继承 `WebViewClient` 自己实现一个子类来使用，也可能会重写 `onReceivedSslError` 方法，这时候，只是 Hook `WebViewClient` 的 `onReceivedSslError` 方法对子类可能并不起作用，所以此脚本还会尝试枚举出属于App自身包的 `WebViewClient` 子类，并把子类的 `onReceivedSslError` 方法也Hook了  

**hook子类的时机和查找子类的方法**  
某些类会在被使用时才载入内存，所以我们尽量在他们可能被实例化的时候再进行查找，此脚本中将 `WebViewClient` 类的构造函数也Hook了，当它的子类被实例化时也会调用父类的构造函数，我们就可以在此时查找它的子类并进行Hook  
使用 `Java.enumerateLoadedClasses` 枚举所有已加载的类，然后使用 `.getSuperclass().getName()` 方法获取某个类的父类名，如果是 `android.webkit.WebViewClient` 就说明该类是我们要找的子类  
使用这种方式会对枚举出来的类名逐个进行上述操作，会特别慢，甚至可能导致卡死，为了缩小查找的范围，脚本中对枚举出来的类名先判断类名中是否包含当前App的包名来判断是不是App包下的类，只对此App自己实现的类进行判断  