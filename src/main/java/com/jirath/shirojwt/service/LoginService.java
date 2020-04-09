package com.jirath.shirojwt.service;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
public interface LoginService {

    /**
     * 登录请求，没有这个用户会进行注册
     * @param code
     * @return
     */
    String login(String code) ;
}
