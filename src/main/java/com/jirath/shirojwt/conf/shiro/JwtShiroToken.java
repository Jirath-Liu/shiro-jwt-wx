package com.jirath.shirojwt.conf.shiro;

import lombok.Data;
import org.apache.shiro.authc.AuthenticationToken;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description: 一个用于Shiro使用的Authentication，因为使用JWT需要有自己的身份信息，所以使用针对Token定制的信息
 */
@Data
public class JwtShiroToken implements AuthenticationToken {
    /**
     * 封装，防止误操作
     */
    private String token;

    /**
     * token作为两者进行提交，使用构造方法进行初始化
     * @param token 用户提交的token
     */
    public JwtShiroToken(String token){
        this.token=token;
    }
    /**
     * 在UserNamePasswordToken中，使用的是账号和密码来作为主体和签证,这里我们使用Token登录
     * 两者的get都是获取token
     */
    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
