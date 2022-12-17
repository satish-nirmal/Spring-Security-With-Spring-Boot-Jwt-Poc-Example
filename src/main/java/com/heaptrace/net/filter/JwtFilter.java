package com.heaptrace.net.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.heaptrace.net.service.CustomUserDetailsService;
import com.heaptrace.net.util.JwtUtil;

@Component
public class JwtFilter extends OncePerRequestFilter{

	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private CustomUserDetailsService customUserDetailsService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		System.out.println("JwtFilter:doFilterInternal()");
		
		String authorizationHeader = request.getHeader("Authorization");
		
		System.out.println("authorizationHeader:: "+authorizationHeader);

		String token = null;
		
		String username = null;
		
		if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			
			System.out.println("In first if condition");
			
			token = authorizationHeader.substring(7);
			
			username = jwtUtil.extractUsername(token);
		}
		
		
		if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			
			System.out.println("In second if condition");
			
			UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
			
			if(jwtUtil.validateToken(token, userDetails)) {
				
				System.out.println("In third if condition");
				
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
				
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				
			}
			
		}
		
		filterChain.doFilter(request, response);
	}

}
