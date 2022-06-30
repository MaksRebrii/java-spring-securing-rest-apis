package io.jzheaux.springsecurity.resolutions;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.stereotype.Component;

@Component
public class ResolutionInitializer implements SmartInitializingSingleton {
	private final ResolutionRepository resolutions;
	private final UserRepository userRepository;

	public ResolutionInitializer(ResolutionRepository resolutions, UserRepository userRepository) {
		this.resolutions = resolutions;
		this.userRepository = userRepository;
	}

	@Override
	public void afterSingletonsInstantiated() {
		this.resolutions.save(new Resolution("Read War and Peace", "user"));
		this.resolutions.save(new Resolution("Free Solo the Eiffel Tower", "user"));
		this.resolutions.save(new Resolution("Hang Christmas Lights", "user"));

		User admin = new User("admin",
				"{bcrypt}$2a$10$bTu5ilpT4YILX8dOWM/05efJnoSlX4ElNnjhNopL9aPoRyUgvXAYa");
		admin.setFullName("Admin Adminson");
		admin.grantAuthority("ROLE_ADMIN");
		this.userRepository.save(admin);

		User user = new User("user",
				"{bcrypt}$2a$10$MywQEqdZFNIYnx.Ro/VQ0ulanQAl34B5xVjK2I/SDZNVGS5tHQ08W");
		user.setFullName("User Userson");
		user.grantAuthority("resolution:read");
		user.grantAuthority("user:read");
		user.grantAuthority("resolution:write");
		this.userRepository.save(user);

		User hasRead = new User("hashread",
				"{bcrypt}$2a$10$MywQEqdZFNIYnx.Ro/VQ0ulanQAl34B5xVjK2I/SDZNVGS5tHQ08W");
		hasRead.setFullName("Has Read");
		hasRead.grantAuthority("resolution:read");
		hasRead.grantAuthority("user:read");
		this.userRepository.save(hasRead);

		User hasWrite = new User("hashwrite",
				"{bcrypt}$2a$10$MywQEqdZFNIYnx.Ro/VQ0ulanQAl34B5xVjK2I/SDZNVGS5tHQ08W");
		hasWrite.setFullName("Has Write");
		user.grantAuthority("resolution:write");
		this.userRepository.save(hasWrite);
	}
}
