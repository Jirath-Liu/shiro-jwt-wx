package com.jirath.shirojwt.conf.shiro;

import com.jirath.shirojwt.conf.exceptionconfig.exception.TokenException;
import com.jirath.shirojwt.conf.jwt.JwtUtil;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description: 继承AuthorizingRealm作为Realm使用，
 */
@Component
public class TokenRealm extends AuthorizingRealm {
    @Autowired
    JwtUtil jwtUtil;

    /**
     * 该方法是为了判断这个主体能否被本Realm处理，判断的方法是查看token是否为同一个类型
     * @param authenticationToken
     * @return
     */
    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        return authenticationToken instanceof JwtShiroToken;
    }


    /**
     * 在需要验证身份进行登录时，会通过这个接口，调用本方法进行审核，将身份信息返回，有误则抛出异常，在外层拦截
     * @param authenticationToken 这里收到的是自定义的token类型，在JwtShiroToken中，自动向上转型。得到的getCredentials为String类型，可以使用toString
     * @return
     * @throws AuthenticationException token异常，可以细化设置
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) {
        String submittedToken=authenticationToken.getCredentials().toString();
        //解析出信息
        String wxOpenId = jwtUtil.getWxOpenIdByToken(submittedToken);
        String sessionKey = jwtUtil.getSessionKeyByToken(submittedToken);
        String userId=jwtUtil.getUserIdByToken(submittedToken);
        //对信息进行辨别
        if (StringUtils.isEmpty(wxOpenId)) {
            throw new TokenException("user account not exits , please check your token");
        }
        if (StringUtils.isEmpty(sessionKey)) {
            throw new TokenException("sessionKey is invalid , please check your token");
        }
        if (StringUtils.isEmpty(userId)) {
            throw new TokenException("userId is invalid , please check your token");
        }
        if (!jwtUtil.verifyToken(submittedToken)) {
            throw new TokenException("token is invalid , please check your token");
        }
        //在这里将principal换为用户的id
        return new SimpleAuthenticationInfo(userId, submittedToken, getName());
    }

    /**
     * 这个方法是用来添加身份信息的，本项目计划为管理员提供网站后台，所以这里不需要身份信息，返回一个简单的即可
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    /**
     * 注意坑点 : 密码校验 , 这里因为是JWT形式,就无需密码校验和加密,直接让其返回为true(如果不设置的话,该值默认为false,即始终验证不通过)
     */
    @Override
    public CredentialsMatcher getCredentialsMatcher() {
        return (token, info) -> true;
    }
}
