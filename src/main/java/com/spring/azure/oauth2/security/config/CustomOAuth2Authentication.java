package com.spring.azure.oauth2.security.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CustomOAuth2Authentication extends AbstractAuthenticationToken {

    private final OAuth2Request storedRequest;
    private final Authentication userAuthentication;

    public CustomOAuth2Authentication(OAuth2Authentication authentication, Set<String> roles) {
        super(authentication.isClientOnly()
                ? authentication.getAuthorities()
                : filter(authentication.getAuthorities(), authentication.getOAuth2Request().getScope(), roles));
        this.storedRequest = authentication.getOAuth2Request();
        this.userAuthentication = authentication.getUserAuthentication();
        setDetails(authentication.getDetails());
        setAuthenticated(authentication.isAuthenticated());
    }

    /**
     * Retains only the authorities from the set of approved scopes and add new authorities mapped.
     */
    private static Collection<GrantedAuthority> filter(Collection<? extends GrantedAuthority> authorities, Set<String> scope, Set<String> newRoles) {
        final List<GrantedAuthority> result = new ArrayList<>();
        result.addAll(
                authorities.stream().
                        filter(authority -> scope.contains(authority.getAuthority())).
                        collect(Collectors.toList()));
        result.addAll(
                newRoles.stream().
                        map(role -> new SimpleGrantedAuthority(role)).
                        collect(Collectors.toList()));
        return result;
    }

    @Override
    public Object getCredentials() {
        return userAuthentication.getCredentials();
    }

    @Override
    public Object getPrincipal() {
        return userAuthentication.getPrincipal();
    }

    public OAuth2Request getStoredRequest() {
        return storedRequest;
    }

    public Authentication getUserAuthentication() {
        return userAuthentication;
    }


}
