// frida 常用函数参考文章
// https://www.anquanke.com/post/id/195869
//

// 枚举所有已加载的类
function enumerateAllClass(keyword = '') {
    // Java.perform（fn）主要用于当前线程附加到Java VM并且调用fn方法 
    Java.perform(function () {

        console.log('');
        console.log('[*] 枚举所有已加载的类');

        console.log('----------');
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (keyword) {
                    if (className.indexOf(keyword) != -1) {
                        console.log("[+] 发现匹配的类：", className);
                    }
                } else {
                    console.log("[+] 发现类：", className);
                }
            },
            onComplete: function () {
                console.log("[!] 枚举结束！");
            }
        });
        console.log('----------');
    });
}

// 枚举所有类加载器
function enumerateAllClassLoader(keyword = '') {
    // Java.perform（fn）主要用于当前线程附加到Java VM并且调用fn方法 
    Java.perform(function () {

        console.log('');
        console.log('[*] 枚举所有类加载器');

        console.log('----------');
        Java.enumerateClassLoaders({
            onMatch: function (classLoader) {
                if (keyword) {
                    if (classLoader.indexOf(keyword) != -1) {
                        console.log("[+] 发现匹配的类加载器：", classLoader);
                    }
                } else {
                    console.log("[+] 发现类加载器：", classLoader);
                }
            },
            onComplete: function () {
                console.log("[!] 枚举结束！");
            }
        });
        console.log('----------');
    });
}

// 查找 className 类的实例化对象
function findAllInstance(className) {
    Java.perform(function () {
        console.log('');
        console.log('[*] 查找类 ' + className + ' 的实例化对象');

        console.log('----------');
        Java.choose(className, {
            onMatch: function (instance) {
                console.log("[+] 发现实例：", instance);
            },
            onComplete: function () {
                console.log("[!] 查找结束!")
            }
        });
        console.log('----------');
    });
}

// 打印类 className 的所有方法、字段
function displayClassAllFieldsAndMethods(className) {
    Java.perform(function () {
        console.log('');
        console.log('[*] 打印类 ' + className + ' 的所有方法、字段');

        console.log('----------');

        var thisClass = Java.use(className);

        console.log('所有的公共的字段(包括父类的)');
        console.log(thisClass.class.getFields().forEach((member) => {
            console.log(member)
        }));
        console.log('所有声明的字段(不包括父类的)');
        console.log(thisClass.class.getDeclaredFields().forEach((member) => {
            console.log(member)
        }));

        console.log('所有的公共的方法');
        console.log(thisClass.class.getMethods().forEach((member) => {
            console.log(member)
        }));
        console.log('所有声明的方法');
        console.log(thisClass.class.getDeclaredMethods().forEach((member) => {
            console.log(member)
        }));

        console.log('所有的公共的构造函数');
        console.log(thisClass.class.getConstructors().forEach((member) => {
            console.log(member)
        }));
        console.log('所有声明的构造函数');
        console.log(thisClass.class.getDeclaredConstructors().forEach((member) => {
            console.log(member)
            console.log(typeof (member))
        }));

        console.log('类');
        console.log(thisClass);
        console.log('----------');
    });

}

// 获取类 className 的所有子类
function getAllSubClass(className) {
    Java.perform(function () {
        console.log('');
        console.log('[*] 获取类 ' + className + ' 所有的子类');

        console.log('----------');
        // 利用java反射
        let reflections = Java.use("org.reflections.Reflections");
        let thisClass = Java.use(className);

        console.log(reflections.getSubTypesOf(thisClass));

        console.log('----------');
    });
}

// 获取当前应用的包名
function getAppPackageName() {
    Java.perform(function () {
        console.log('');
        console.log('[*] 获取当前应用的包名');

        console.log('----------');
        let activityThread = Java.use("android.app.ActivityThread");
        // console.log(activityThread, typeof (activityThread));
        let packageName = activityThread.currentApplication().getApplicationContext().getPackageName();
        // console.log(packageName, typeof (packageName));
        activityThread.$dispose();
        console.log('----------');
        return packageName
    });
}

// 弹窗交互
function dialogInteract() {
    Java.perform(function () {
        console.log('');
        console.log('[*] 弹窗交互');

        console.log('----------');
        // 定义自己的Dialog类
        // var TrustManager = Java.registerClass({
        //     name: 'com.sensepost.test.TrustManager',
        //     implements: [X509TrustManager],
        //     methods: {
        //         checkClientTrusted: function (chain, authType) {
        //             console.log("! 调用了 TrustManager.checkClientTrusted");
        //         },
        //         checkServerTrusted: function (chain, authType) {
        //             console.log("! 调用了 TrustManager.checkServerTrusted");
        //         },
        //         getAcceptedIssuers: function () {
        //             console.log("! 调用了 TrustManager.getAcceptedIssuers");
        //             return [];
        //         }
        //     }
        // });
        // let looper = Java.use("android.os.Looper");
        // console.log(looper, typeof (looper));
        // let tmp = looper.prepare();
        // console.log(tmp, typeof (tmp));
        let activityThread = Java.use("android.app.ActivityThread");
        console.log(activityThread, typeof (activityThread));
        // let context = activityThread.currentApplication().getApplicationContext();
        let context = activityThread.currentApplication();
        console.log(context, typeof (context));
        // let activity = Java.use('android.app.Activity');
        // console.log(activity, typeof (activity));
        // console.log(activity.ACTIVITY_SERVICE, typeof (activity.ACTIVITY_SERVICE));
        // let systemService = context.getSystemService(activity);
        // console.log(systemService, typeof (systemService));
        let alertDialog = Java.use("android.app.AlertDialog").$new(context);
        console.log(alertDialog, typeof (alertDialog));
        // alertDialogBuilder
        // let packageName = activityThread.currentApplication().getApplicationContext().getPackageName();

        // console.log(packageName, typeof (packageName));
        alertDialog.show();
        alertDialog.$dispose();
        // looper.$dispose();
        activityThread.$dispose();
        console.log('----------');
        // return packageName
    });
}

function main() {
    if (Java.available) {
        console.log("[!] Android系统版本号：", Java.androidVersion);
        // enumerateAllClass('AlertDialog');
        // enumerateAllClassLoader();
        // findAllInstance('android.content.Context');
        // findAllInstance('android.app.Application');
        displayClassAllFieldsAndMethods('com.dbank.hqdbank.webcomponet.MBankWebViewClient');
        // getAllSubClass('com.dbank.hqdbank.webcomponet.MBankWebViewClient');
        // getAppPackageName();
        // dialogInteract();
    } else {
        console.log("[!] No Java!")
    }
}

// for (var j = 0; j < arguments.length; j++) {
//     console.log("arg[" + j + "]: " + arguments[j] + " => " + JSON.stringify(arguments[j]));
// }
// let retval = this.$init.apply(this, arguments);
// console.log("ret: " + retval);
// return retval

// setImmediate(main)
main()