package com.jirath.shirojwt.vo.error;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
public class ErrorInfo<T> {


    public static final Integer OK = 0;
    public static final Integer ERROR = 100;

    private Integer code;
    private String message;
    private String url;
    private T data;

}
