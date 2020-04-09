# 使用Shiro+JWT完成的微信小程序的登录

微信小程序用户登陆，完整流程可参考下面官方地址，本例中是按此流程开发
https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html

## 你需要了解的点

微信小程序的登录流程

https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html

Shiro的基础知识

https://shiro.apache.org/10-minute-tutorial.html

JWT以及Token

https://jwt.io/introduction/

## 项目的流程

1.  调用 [wx.login()](https://developers.weixin.qq.com/miniprogram/dev/api/open-api/login/wx.login.html) 获取 **临时登录凭证code** ，并回传到开发者服务器。
2.  访问login接口，并将code给后台
3.  被JwtShirioFilter拦截(在shiro配置中配置的)，查看有没有token在Header
4.  有则自动执行登录操作，核实token的合法性，并刷新token
5.  没有则被controller拦截进入service中进行登录
6.  使用code获取用户信息，默认初始化了一些信息（可以修改的）
7.  生成token（会存至redis）
8.  返回token

## 本项目的结构

项目分包：

1.  conf 项目的配置
    1.  exceptoionconfig 配置了异常的抛出，使用@ControllerAdvice进行拦截统一处理
    2.  jwt 包含一个jwt工具类，在使用时会与redis连接，存储、验证与生成token
    3.  shiro 是本项目配置的核心，其中关闭了session管理，使用jwt来完成验证，包含一个自定的应用于shiro的token
    4.  RestTemplateConfig 使用Spring
2.  enums 包含了需要的枚举类
3.  vo
    1.  wxapi 包含了一个请求微信后台需要的结果类

不可修改的模块：有JWT与Shiro的类别以及配置模块





