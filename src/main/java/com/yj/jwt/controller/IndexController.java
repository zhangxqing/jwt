package com.yj.jwt.controller;

import com.alibaba.fastjson.JSON;
import com.yj.jwt.entity.BusinessException;
import com.yj.jwt.entity.User;
import com.yj.jwt.utils.CommonUtils;
import com.yj.jwt.utils.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class IndexController {
	private final static Logger logger = LoggerFactory.getLogger(IndexController.class);

	@Value(value = "${TTL}")
	private String TTL;

	@Value(value = "${refreshTTL}")
	private String refreshTTL;

	@RequestMapping("/index")
	@ResponseBody
	public String index(HttpServletRequest request, HttpServletResponse response) {
		String token = CommonUtils.getCookie(request, "token");
		User user=JwtUtil.getJwtUser(token);
		return "Hello:"+user.getName();
	}

	@RequestMapping("/pwdError")
	@ResponseBody
	public String error(HttpServletRequest request, HttpServletResponse response) {
		return "密码错误!";
	}
	
	@RequestMapping("/sysError")
	@ResponseBody
	public String sysError(HttpServletRequest request, HttpServletResponse response) {
		return "系统异常!";
	}

	@RequestMapping("/loginPage")
	@ResponseBody
	public String loginPage(HttpServletRequest request, HttpServletResponse response) {
		return "跳转到登录页面";
	}

	@RequestMapping("/login")
	public String login(HttpServletRequest request, HttpServletResponse response, @RequestParam String pwd) {
		if ("123456".equals(pwd)) {
			User user = new User();
			user.setId("1");
			user.setName("TestUser");
			String token;
			String refreshToken;
			try {
				String userStr=JSON.toJSONString(user);  
				token = JwtUtil.createJWT(user.getId(), userStr, Long.parseLong(TTL) * 60000);
				refreshToken = JwtUtil.createJWT(user.getId(), userStr, Long.parseLong(refreshTTL) * 60000);
				CommonUtils.addCookie(response, "token", token);
				CommonUtils.addCookie(response, "refreshToken", refreshToken);
			} catch (BusinessException e) {
				logger.info("发生异常：" + e.getMessage());
			} catch (Exception e) {
				e.printStackTrace();
			}
			return "redirect:/index";
		}
		return "redirect:/pwdError";
	}
}
