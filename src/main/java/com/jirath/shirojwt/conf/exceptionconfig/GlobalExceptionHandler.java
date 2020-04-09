package com.jirath.shirojwt.conf.exceptionconfig;

import com.jirath.shirojwt.conf.exceptionconfig.exception.TokenException;
import com.jirath.shirojwt.conf.exceptionconfig.exception.WxApiException;
import com.jirath.shirojwt.util.enums.CodeEnum;
import com.jirath.shirojwt.vo.ResultVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Jirath
 * @date 2020/4/9
 * @description:
 */
@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    @ExceptionHandler(value = WxApiException.class)
    @ResponseBody
    public ResultVo jsonErrorHandler(HttpServletRequest req, WxApiException e) throws Exception {
        logger.error("微信api访问异常！原因是:",e.getMessage());
        e.printStackTrace();
        return ResultVo.builder().msg(CodeEnum.ERROR_WX_CODE.getResultMsg()).code(CodeEnum.ERROR_WX_CODE.getResultCode()).build();
    }
    @ExceptionHandler(value = TokenException.class)
    @ResponseBody
    public ResultVo tokenErrorHandler(HttpServletRequest req, WxApiException e) throws Exception {
        logger.error("token异常！原因是:",e.getMessage());
        e.printStackTrace();
        return ResultVo.builder().msg(CodeEnum.ERROR_TOKEN.getResultMsg()).code(CodeEnum.ERROR_TOKEN.getResultCode()).build();
    }
    /**
     * 处理其他异常
     * @param req
     * @param e
     * @return
     */
    @ExceptionHandler(value =Exception.class)
    @ResponseBody
    public ResultVo exceptionHandler(HttpServletRequest req, Exception e){
        logger.error("未知异常！原因是:",e);
        return ResultVo.builder().msg(CodeEnum.INTERNAL_SERVER_ERROR.getResultMsg()).code(CodeEnum.INTERNAL_SERVER_ERROR.getResultCode()).build();
    }

}
