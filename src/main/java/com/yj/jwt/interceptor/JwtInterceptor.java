package com.yj.jwt.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import com.alibaba.fastjson.JSON;
import com.yj.jwt.entity.BusinessException;
import com.yj.jwt.utils.CommonUtils;
import com.yj.jwt.utils.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtInterceptor implements HandlerInterceptor {

	private final static Logger logger = LoggerFactory.getLogger(JwtInterceptor.class);

	@Value(value = "${TTL}")
	private String TTL;

	@Value(value = "${refreshTTL}")
	private String refreshTTL;

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object o) throws Exception {
		String token = CommonUtils.getCookie(request, "token");
		String refreshToken = CommonUtils.getCookie(request, "refreshToken");
		try {
			JwtUtil.parseJWT(token);
			try {
				JwtUtil.parseJWT(refreshToken);
			} catch (ExpiredJwtException e) {
				logger.info("refreshToken过期，重新构造token和refreshToken");
				String userStr = JSON.toJSONString(JwtUtil.getJwtUser(token));
				token = JwtUtil.createJWT(JwtUtil.getJwtUser(token).getId(), userStr, Long.parseLong(TTL) * 60000);
				refreshToken = JwtUtil.createJWT(JwtUtil.getJwtUser(token).getId(), userStr,
						Long.parseLong(refreshTTL) * 60000);
				CommonUtils.addCookie(response, "token", token);
				CommonUtils.addCookie(response, "refreshToken", refreshToken);
				return true;
			}
		} catch (ExpiredJwtException e) {
			logger.info("token过期");
			response.sendRedirect("/loginPage");
		} catch (BusinessException e) {
			logger.info("系统发生异常:"+e.getMessage());
			response.sendRedirect("/sysError");
		} catch (Exception e) {
			logger.info("系统发生异常");
			response.sendRedirect("/sysError");
		}
		return true;
	}

	@Override
	public void afterCompletion(HttpServletRequest arg0, HttpServletResponse arg1, Object arg2, Exception arg3)
			throws Exception {
	}

	@Override
	public void postHandle(HttpServletRequest arg0, HttpServletResponse arg1, Object arg2, ModelAndView arg3)
			throws Exception {
	}
}
