package com.jirath.shirojwt.conf.exceptionconfig.exception;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */

public class WxApiException extends RuntimeException {
    public WxApiException(){super();}
    public WxApiException(String message) {
        super(message);
    }
    public WxApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
