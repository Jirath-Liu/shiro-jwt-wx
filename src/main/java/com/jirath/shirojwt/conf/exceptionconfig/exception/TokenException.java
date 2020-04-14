package com.jirath.shirojwt.conf.exceptionconfig.exception;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
public class TokenException extends Exception {
    public TokenException(){super();}
    public TokenException(String message) {
        super(message);
    }
    public TokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
