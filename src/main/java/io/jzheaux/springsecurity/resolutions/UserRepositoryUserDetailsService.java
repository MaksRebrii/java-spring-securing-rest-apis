package io.jzheaux.springsecurity.resolutions;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

public class UserRepositoryUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserRepositoryUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userRepository.findByUsername(username)
                .map(this::map)
                .orElseThrow(() -> new UsernameNotFoundException("invalid user"));
    }

    private BridgeUser map(User user) {
        Collection<GrantedAuthority> authorities = new HashSet<>();
        for (UserAuthority userAuthority : user.getUserAuthorities()) {
            String authority = userAuthority.getAuthority();
            if ("ROLE_ADMIN".equals(authority)){
                authorities.add(new SimpleGrantedAuthority("resolution:read"));
                authorities.add(new SimpleGrantedAuthority("resolution:write"));
            }

            authorities.add(new SimpleGrantedAuthority(authority));
        }
        return new BridgeUser(user, authorities);
    }

    private static class BridgeUser extends User implements UserDetails {

        private final Collection<GrantedAuthority> authorities;

        public BridgeUser(User user, Collection<GrantedAuthority> authorities) {
            super(user);
            this.authorities = authorities;
        }

        public List<GrantedAuthority> getAuthorities() {
            return this.userAuthorities.stream()
                    .map(UserAuthority::getAuthority)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        @Override
        public boolean isAccountNonExpired() {
            return this.enabled;
        }

        @Override
        public boolean isAccountNonLocked() {
            return this.enabled;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return this.enabled;
        }


    }
}
