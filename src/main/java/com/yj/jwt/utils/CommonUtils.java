package com.yj.jwt.utils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CommonUtils {

	public static String getCookie(HttpServletRequest request, String name) {
		Cookie cookies[] = request.getCookies();
		Cookie sCookie = null;
		String sid = null;
		if (cookies != null && cookies.length > 0) {
			for (int i = 0; i < cookies.length; i++) {
				sCookie = cookies[i];
				if (name.equals(sCookie.getName())) {
					sid = sCookie.getValue();
					break;
				}
			}
		}
		return sid;
	}

	public static void addCookie(HttpServletResponse response, String name, String value) {
		Cookie cookie = new Cookie(name, value);
		cookie.setMaxAge(-1);
		cookie.setPath("/");//可在同一应用服务器内共享cookie
		cookie.setHttpOnly(true);//防御XSS攻击
		//cookie.setDomain(".taobao.com");cookie跨域访问
		response.addCookie(cookie);
	}
}
