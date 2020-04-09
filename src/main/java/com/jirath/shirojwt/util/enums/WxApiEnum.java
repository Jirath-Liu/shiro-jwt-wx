package com.jirath.shirojwt.util.enums;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
public enum WxApiEnum {
    LOGIN_URL("https://api.weixin.qq.com/sns/jscode2session");
    private final String string;
    WxApiEnum(String s){
        this.string=s;
    }

    public String getString() {
        return string;
    }
}
