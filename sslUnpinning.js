// 用法
//   frida -U -f [AppPackageName] --no-pause -l sslUnpinning.js
// 或者自行查看frida的用法

// 记录某个类的子类是否已经枚举并 hook，如果已经hook就不再重复尝试 hook
var hookedClassMethod = []

// 获取当前应用的包名
function getAppPackageName() {
    let activityThread = Java.use("android.app.ActivityThread");
    let packageName = activityThread.currentApplication().getApplicationContext().getPackageName();
    activityThread.$dispose();
    return packageName
}

// 枚举所有已加载的类
function enumerateAllClass(keyword = '') {
    let allClass = [];
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (keyword) {
                if (className.indexOf(keyword) != -1) {
                    allClass.push(className);
                }
            } else {
                allClass.push(className);
            }
        },
        onComplete: function () {}
    });
    return allClass;
}

// hook className 类的 methodName 方法
function hookClassMethod(className, methodName, hookImplementation) {
    console.log("==========");
    console.log("[*] 尝试hook " + className + " 类的所有 " + methodName + " 方法重载!")
    let hookClass = Java.use(className);
    let hookMethod = hookClass[methodName];
    if (!hookMethod) {
        return;
    }
    hookMethod.overloads.forEach((hookMethodOverload) => {
        // console.log("[*] 开始hook " + hookClass + " -> " + hookMethodOverload + " " + JSON.stringify(hookMethodOverload._p));
        let _methodName = hookMethodOverload._p[0];
        let _methodFormalParams = [];
        hookMethodOverload._p[5].forEach((tmpParams) => {
            _methodFormalParams.push(tmpParams.className);
        });
        console.log("[*] 开始hook " + hookClass + " -> " + _methodName + "(" + _methodFormalParams.join(", ") + ")");

        hookMethodOverload.implementation = function () {
            console.log('****' + className + '.' + methodName + '****');
            let retval = hookImplementation(this, this[methodName], arguments);
            for (var j = 0; j < arguments.length; j++) {
                console.log("[>] 参数[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
            }
            console.log("[<] 返回值", retval);
            console.log('********');
            return retval;
        }

        console.log("[+] 已hook " + hookClass + " -> " + _methodName + "(" + _methodFormalParams.join(", ") + ")");
    })
    console.log("[+] 已经hook " + className + " 类的所有 " + methodName + " 方法重载!")
    console.log("==========");
    hookClass.$dispose();
}

// 判断 className1 是不是 className2 的子类
function isSubClass(className1, className2) {
    let ret = false;
    var delim = className1.lastIndexOf(".");
    if (delim === -1) return ret;
    try {
        let class1 = Java.use(className1);
        try {
            ret = class1.class.getSuperclass().getName() == className2;
            class1.$dispose();
        } catch (err) {
            // console.log(1, err);
            class1.$dispose();
        }
    } catch (err) {
        // console.log(2, err);
    }
    return ret;
}

Java.perform(function () {
    console.log('')
    console.log('===')
    console.log('* hook 常见的证书Pinning方法 和 webviewClient 的证书错误事件处理函数 *')
    console.log('===')

    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    // build fake trust manager
    var TrustManager = Java.registerClass({
        name: 'com.sensepost.test.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {
                console.log("[!] 调用了 TrustManager.checkClientTrusted");
            },
            checkServerTrusted: function (chain, authType) {
                console.log("[!] 调用了 TrustManager.checkServerTrusted");
            },
            getAcceptedIssuers: function () {
                console.log("[!] 调用了 TrustManager.getAcceptedIssuers");
                return [];
            }
        }
    });
    // pass our own custom trust manager through when requested
    var TrustManagers = [TrustManager.$new()];
    try {
        // javax.net.ssl.SSLContext.init(keyManager, trustManager, secureRandom)
        hookClassMethod('javax.net.ssl.SSLContext', 'init', function (thisObject, thisMethod, allArguments) {
            console.log('[!] 拦截到 trustmanager request');
            thisMethod.call(thisObject, allArguments[0], TrustManagers, allArguments[2]);
        });
        console.log('[+] 已 hook okhttp3 pinning')
    } catch (err) {
        console.log('[-] 无法 hook okhttp3 pinner')
    }
    console.log('[+] 已 hook custom trust manager');

    // okhttp3
    try {
        // okhttp3.CertificatePinner.check(str)
        hookClassMethod('okhttp3.CertificatePinner', 'check', function (thisObject, thisMethod, allArguments) {
            console.log('[!] 拦截到 okhttp3.CertificatePinner check() 方法: ' + allArguments[0]);
            return;
        });
        console.log('[+] 已 hook okhttp3 pinning')
    } catch (err) {
        console.log('[-] 无法 hook okhttp3 pinner')
    }

    // trustkit
    try {
        // com.datatheorem.android.trustkit.pinning.OkHostnameVerifier.verify(str) {
        hookClassMethod("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", "verify", function (thisObject, thisMethod, allArguments) {
            console.log('[!] 拦截到 trustkit verify() 方法: ' + allArguments[0]);
            return true;
        });
        console.log('[+] 已 hook trustkit pinning')
    } catch (err) {
        console.log('[-] 无法 hook trustkit pinner')
    }

    // TrustManagerImpl
    try {
        // com.android.org.conscrypt.TrustManagerImpl.verifyChain(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData)
        hookClassMethod('com.android.org.conscrypt.TrustManagerImpl', 'verifyChain', function (thisObject, thisMethod, allArguments) {
            console.log('[!] 拦截到 TrustManagerImp verifyChain() 方法: ' + allArguments[2]);
            return allArguments[0];
        });
        console.log('[+] 已 hook TrustManagerImpl pinning')
    } catch (err) {
        console.log('[-] 无法 hook TrustManagerImpl')
    }

    // Appcelerator
    try {
        // appcelerator.https.PinningTrustManager.checkServerTrusted()
        hookClassMethod('appcelerator.https.PinningTrustManager', 'checkServerTrusted', function (thisObject, thisMethod, allArguments) {
            console.log('[!] 拦截到 Appcelerator checkServerTrusted() 方法');
        });
        console.log('[+] 已 hook Appcelerator pinning')
    } catch (err) {
        console.log('[-] 无法 hook Appcelerator pinning')
    }

    // Hook WebViewClient 的 onReceivedSslError
    hookClassMethod('android.webkit.WebViewClient', 'onReceivedSslError', function (thisObject, thisMethod, allArguments) {
        console.log('[!] 拦截到 WebViewClient onReceivedSslError() 方法');
        // 忽略SSL错误
        console.log('[!] 忽略SSL错误');
        allArguments[1].proceed();
        let retval = thisMethod.apply(thisObject, allArguments);
        return retval;
    });

    // Hook WebViewClient 的 构造函数，当 WebViewClient 构造函数被调用时，再枚举所有被加载的类，从而找到 WebViewClient 的子类，并将子类中相关的方法也 hook 了
    // Q: 为什么等到调用构造函数时才尝试 hook 子类
    // A: 因为某些类会在调用时才载入内存，未调用时 Java.enumerateLoadedClasses 是枚举不到的！
    hookClassMethod('android.webkit.WebViewClient', '$init', function (thisObject, thisMethod, allArguments) {
        if (hookedClassMethod.indexOf('android.webkit.WebViewClient') == -1) {
            console.log('[!] 拦截到 WebViewClient 构造函数');
            let hookFlag = false;
            let allClass = enumerateAllClass();
            console.log("[!] 正在查找 WebViewClient 子类，可能会很久，期间手机可能会黑屏卡住，是正常现象！");
            let thisAppPackageName = getAppPackageName();
            allClass.forEach((tmpClass) => {
                if (tmpClass.indexOf(thisAppPackageName) != -1 && isSubClass(tmpClass, 'android.webkit.WebViewClient')) {
                    console.log("[+] 发现子类: ", tmpClass);
                    // hook 子类的 onReceivedSslError
                    hookClassMethod(tmpClass, "onReceivedSslError", function (thisObject, thisMethod, allArguments) {
                        console.log('[!] 拦截到 ' + tmpClass + ' onReceivedSslError() 方法');
                        // 忽略SSL错误
                        console.log('[!] 忽略SSL错误');
                        allArguments[1].proceed();
                        let retval = thisMethod.apply(thisObject, allArguments);
                        return retval;
                    });

                    hookFlag = true;
                }
                // }
            });
            if (hookFlag) {
                hookedClassMethod.push('android.webkit.WebViewClient');
            }
            console.log("[!] 查找结束！");
        } else {
            // console.log("[!] 子类已hook，不再重复枚举hook!");
        }
        let retval = thisMethod.apply(thisObject, allArguments);
        return retval;
    });
});